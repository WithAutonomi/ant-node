# Finding 5: Merkle `already_stored` lie

**Severity:** MEDIUM-HIGH (requires Sybil majority in target's close group)
**Category:** Data loss (silent)
**PoC:** `tests/poc_merkle_already_stored_lie.rs` (3 tests, all pass)

## Root cause

`ChunkQuoteResponse::Success { quote: Vec<u8>, already_stored: bool }`
(node side: `src/storage/handler.rs:382-388`).

The `already_stored` flag sits **outside** the signed quote envelope. The
signed `quote` payload covers `(content, timestamp, price, rewards_address)` —
but never the `already_stored` flag. The flag is a bare boolean returned by
`storage.exists(&request.address)` from the responder's local LMDB, with no
binding to anything.

## Attack

A node positioned in a target client's close-group view returns
`Success { quote: <valid signed quote>, already_stored: true }` for chunks it
does not in fact hold. The signed quote is valid (so it passes binding +
signature checks); the `already_stored` bit is the lie.

The client's preflight planner (ant-client/ant-core/src/data/client/quote.rs)
collects votes and requires `close_group_stored >= CLOSE_GROUP_MAJORITY`
(5 of 8) before treating the chunk as stored (`quote.rs:372`). So a single
lying peer is not enough — but a Sybil coalition of 5/8 in close group is.

Once the threshold is met, the client:
- Drops the chunk from the merkle payment plan (no payment).
- Drops the chunk from the upload set (no PUT).
- Reports the upload as successful.

The chunk is never stored anywhere on the network. Silent data loss.

## Quantified impact

- Per-key Sybil capability: 5/8 close-group peer IDs. Same cost as Finding 3.
- Attacker cost beyond Sybil placement: one boolean flip in the responder
  code at `src/storage/handler.rs:387` — no protocol changes, no extra wire
  traffic.
- Per-attack on-chain footprint: **zero**.
- Detection: zero client-side recourse — the upload returns success, the
  client has no possession-proof challenge to verify the claim.

The 5/8 threshold downgrades this from "single bit flip → silent loss" (which
the agent initially claimed) to "Sybil majority in close group → silent loss".
Still serious — the same Sybil capability supports Finding 3 — but not a
single-peer attack.

## Fix space

Two options; either closes it.

1. **Move the flag inside the signed quote envelope** AND **bind it to a client-
   supplied challenge**. The quote now signs over
   `(content, timestamp, price, rewards_address, already_stored, possession_token)`
   where `possession_token = HMAC(chunk_blake3, client_nonce)`. A node that
   doesn't hold the chunk can't compute `possession_token`. The client supplies
   `client_nonce` in the request, so replay across nonces is impossible.
2. **Drop the flag entirely.** Let storage-time dedup at PUT handle idempotency:
   the responder accepts a duplicate PUT but treats it as a no-op. Cost: one
   signed quote per chunk, one PUT per chunk. The preflight optimization was
   added for resumable uploads — there are other ways to detect resume (client
   tracks per-chunk receipt persistence; PR #88 already does this).

Fix 1 preserves the optimization but adds one HMAC per chunk on the responder.
Fix 2 trades a small efficiency loss for a smaller attack surface. Worth
discussing with Nic and Mick — the preflight planner was their work.

## Related

Same Sybil threshold and same close-group capability as Finding 3 (paid-list
attestation forgery). A coalition that can land Finding 3 can land Finding 5.

## Post-fix test

`poc_merkle_already_stored_lie_fabricated_response_is_indistinguishable` must
FAIL: a fabricated `already_stored=true` response without a valid possession
token must be rejected by the client (or by the protocol if the flag is removed).
