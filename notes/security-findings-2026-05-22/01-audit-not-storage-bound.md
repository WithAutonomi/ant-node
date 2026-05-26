# Finding 1: Audit not storage-bound

**Severity:** HIGH
**Category:** Lazy-node defeats audit; data loss
**PoCs:**
- `tests/poc_lazy_audit_collusion.rs` (4 tests, all pass)
- `tests/poc_data_loss_transient_holder.rs` (3 tests, all pass)

## Root cause

`compute_audit_digest = BLAKE3(nonce || challenged_peer_id || key || record_bytes)`
(`src/replication/protocol.rs:331`).

The digest proves the responder **can produce these bytes right now**. It does not
prove the responder **durably stored them**. Every input to the hash is either in
the challenge message (`nonce`, `challenged_peer_id`, `key`) or is the chunk
content itself.

Two profiles share this root cause.

## 1a. Lazy node via on-demand fetch (defeats audit)

A node holding zero local chunks answers audits correctly by fetching the bytes
from any honest neighbour during the challenge window, then computing the
digest with its own peer ID.

- Audit response timeout: `audit_response_base (10s) + audit_response_per_key (20ms) * N`.
- Audit sample size: `floor(sqrt(total_keys_claimed))`. A node "claiming" 10,000 keys is
  challenged on at most 100 keys, so the budget is ~12s.
- PoC times a 100-key challenge with 50ms parallel fetches: finishes in <500ms.
  ~200× headroom.

The anti-relay guard at `audit.rs:548` (`challenged_peer_id != self_peer_id → Rejected`)
does **not** stop this. It stops a third party from *forwarding* a response on the
lazy node's behalf. The lazy node IS the legitimate target; it just sources the
bytes from elsewhere and computes the digest locally with its own peer ID baked in.

## 1b. Transient-holder prune forgery (data loss)

A coalition of ≥7 peers in close group of key K each fetches K once and keeps the
bytes in RAM. When the honest holder's prune cycle requires all 7 close-group
peers to confirm they store K via an audit-style challenge, every Sybil answers
correctly from memory. Honest holder prunes. Sybils drop bytes. Real data loss.

Pruning hardening that does **not** detect this:
- All-7-peer prune confirmation: every Sybil answers correctly.
- 3-day hysteresis: coordination overhead is bounded RAM, not storage time.
- Bootstrap-claim closure: orthogonal — Sybils answer cleanly.
- Mature repair-proof: records that we sent a hint; doesn't require storage
  acknowledgement from the peer.

## Why the multi-key bundle does not defend

A natural intuition: "the audit samples many keys at once, so a lazy node would
need to fetch all of them, which takes too long." This fails for three reasons:

1. **Parallel fetch.** Kad GETs are independent and parallelisable across N keys
   without serialising. The PoC measures 100 parallel 50ms fetches → ~50ms total.
2. **Sample size is sqrt-scaled.** A 10,000-key node is challenged on 100 keys,
   not 10,000. Even serial fetches at 50ms each = 5s, half the 10s base budget.
3. **Per-key budget is 20ms** — added precisely because the protocol *expects*
   the responder to do work per key. The window is calibrated for honest disk
   reads, but it equally fits cooperative network fetches.

A defender could shrink the per-key budget below plausible RTT (say 2ms),
but that punishes honest peers with slow storage and only buys a small
constant against a determined attacker. Doesn't close the class.

## Why this matters

Pure freerider economics:
- Lazy node pays O(bandwidth-on-demand) instead of O(disk × retention).
- Earns rewards for chunks it doesn't hold as long as some honest peer in the
  close group holds them (which is the normal state of the network).
- The audit log shows "passed" → trust score rises → keeps earning.
- Stops working only when *every* close-group peer goes lazy at once — which
  is what causes the transient-holder data loss.

## Fix space

The protocol must tie *proof of digest* to *proof of prior local possession*.

1. **Pre-committed local proofs.** Each node commits to a Merkle root over
   `(K_i, BLAKE3(K_i || record_bytes_i))` at admission time and refreshes it on a
   slow schedule (e.g. every audit cycle epoch). Audits sample over the committed
   set and require a Merkle path. An on-demand fetcher cannot pre-commit without
   first fetching everything — which costs them the disk anyway.
2. **Bandwidth-bound PoR.** Use a proof of retrievability scheme designed against
   outsourcing (cf. Walrus / Red Stuff). Larger change.
3. **Random-offset spot reads.** Challenge requires the responder to return
   `record_bytes[offset..offset+N]` for an attacker-unpredictable offset, with
   the offset baked into the digest. Still vulnerable to on-demand fetch but the
   per-chunk bandwidth cost increases proportionally with audit frequency.

Option 1 is the cleanest fix in this codebase. Option 3 is a one-day intermediate
mitigation that meaningfully raises the attacker's bandwidth bill.

## Post-fix test

The assertion `lazy_response_matches_honest_response` in `poc_lazy_audit_collusion.rs`
must FAIL: a node that did not pre-commit and store the data must be unable to
produce a valid response within the protocol window.

`poc_transient_holders_satisfy_all_prune_preconditions` must FAIL: a RAM-only
coalition must be unable to satisfy all 7 prune confirmations.
