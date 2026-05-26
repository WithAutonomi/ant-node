# Finding 3: Unauthenticated paid-list attestation forgery

**Severity:** HIGH
**Category:** Data loss / audit subversion
**PoC:** `tests/poc_paid_list_attestation_forgery.rs` (4 tests, all pass)

## Root cause

`KeyVerificationResult.paid: Option<bool>` (`src/replication/protocol.rs:215-226`)
is a peer-claimed boolean with no signature, no payment proof, no Merkle witness.
Peers self-attest "I have K in my PaidForList".

The verification cycle in `src/replication/mod.rs:2174-2189` writes K into the
local LMDB-backed `PaidForList` whenever the per-key outcome is
`PaidListVerified`. The verifier reaches that outcome via local-majority quorum
(`paid_list_close_group_size / 2 + 1` = **5** at default group size 8) of
peer-claimed `paid: Some(true)` votes — no proof attached.

## Attack

1. Sybil coalition places 5 nodes in `PaidCloseGroup(K*)` for a chosen K*.
2. Honest victim runs a verification cycle for K* (any keystream that admits K*
   reaches this code path — e.g. an inbound hint that triggers re-verification).
3. The 5 Sybils each return `paid: Some(true)` for K*. Quorum is reached.
4. `evaluate_key_evidence` returns `PaidListVerified { sources: empty }` — no
   presence votes, but the predicate doesn't require them.
5. `run_verification_cycle` calls `paid_list.insert(K*)`. Persisted to LMDB.

The orphan entry has three downstream effects:

1. **Persists across restart.** No payment proof is stored — the API physically
   can't store one, since none was provided. After a restart there's no way to
   re-validate, but no validation is attempted either.
2. **Permanently opens admission fast-path.** `src/replication/admission.rs:128-133`
   skips the `is_in_paid_close_group` check if the key is already in PaidForList.
   Any future paid-only hint for K* from any peer in LocalRT auto-admits.
3. **Corrupts audit & pruning logic for K*.** "K* is paid" is true network-wide
   for the victim, but no chunk exists anywhere. Audits of K* find no chunk;
   pruning treats it as paid-protected. The chunk that should be there never
   was.

## Quantified impact

Per-key attack cost: control 5 peer IDs in K*'s `PaidCloseGroup` (a 256-bit XOR
distance bucket). At current network size, single-key sybil placement is
cheap (PeerId-grinding against a 32-byte address space, no proof-of-work).

Corruption is sticky across restart. Downstream effects compound: every
subsequent paid-only flow involving K* skips the close-group check.

## Fix space

Two independent fixes; either closes this. Both have non-trivial cost.

1. **Bind every PaidForList entry to a verifiable payment proof.** Persist the
   on-chain payment proof (or a Merkle path to it) alongside the key in LMDB.
   Re-verify lazily on first use after restart. Reject `paid: Some(true)`
   responses that don't carry a proof. Cost: storage growth proportional to
   paid-list size; verification cost on cache miss.
2. **Require non-empty `sources` (co-located presence quorum) before insert.**
   Treat "K is paid" as a 2-of-2 predicate: `paid: Some(true)` AND `present: true`
   from a quorum of the same close group. At minimum the coalition would have to
   actually store the chunk to pass the `present` check. Doesn't fully prevent
   the attack (a coalition that DOES store K can still over-attest paid status
   for other keys via separate cycles) but it stops the no-chunk case.

Fix 1 is correct but is a larger schema change. Fix 2 is a one-line predicate
change in `evaluate_key_evidence` and ships today.

## Related

This is the same Sybil-coalition threshold (5/8) as Finding 5 (merkle
`already_stored` lie). A coalition that has the close-group capability to land
this attack can land both.

## Post-fix test

`poc_forged_paid_confirmations_yield_paid_list_verified_with_no_chunk` must
FAIL: `evaluate_key_evidence` must not reach `PaidListVerified` from paid
attestations alone.

`poc_orphan_paid_entry_persists_across_restart_with_no_proof` must FAIL: after
restart the entry must either be removed or re-validated from a persisted proof.
