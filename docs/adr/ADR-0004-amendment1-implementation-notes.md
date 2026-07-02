# ADR-0004 Amendment 1 — implementation & test checklist (not part of the ADR)

Design rationale is the two rules in the ADR amendment. These notes capture the
implementation precision surfaced by adversarial review, to be enforced in code
(Phase 2) and tests (Phase 3). They are intentionally out of the ADR to keep it
terse.

## Persistence (rule 2: retention survives restart)
- Persist a paid-pin ledger separate from the 2-slot gossip cache, keyed by
  commitment_pin, holding the FULL canonical signed commitment (leaves + tree, so
  any future nonce's subtree_plan is computable) and the leaf keys; reload before
  serving audits. Bytes come from the durable chunk store.
- Byte-pinning: extend the pruner is_held veto to every committed leaf of every
  live paid pin until its deadline, from the persisted ledger; survives restart
  and retire_current. Unpaid/replicated data keeps existing pruning.
- Commit/quote only over already-durable bytes; write the ledger entry
  (fsync -> atomic rename -> dir fsync) BEFORE the quote goes on the wire.
- Crash recovery matrix: bytes+ledger present -> answer; ledger torn, bytes ok ->
  rebuild ledger from the durable sidecar; sidecar torn, bytes ok -> rebuild if
  root matches else stop quoting; bytes missing -> genuine loss (convicted if it
  answers definitively). While recovery is AMBIGUOUS the responder must NOT return
  a definitive UnknownCommitment for an admitted paid pin (return non-response ->
  timeout lane) so an honest torn write never self-convicts.
- Responder audit path consults the persisted ledger authoritatively; it
  dominates ResponderCommitmentState::lookup_by_hash for paid audit contexts.
- Timestamps migrate Instant -> persisted wall-clock + monotonic runtime view;
  clamp future stamps; backward jump keeps the longer window.

## Answerability >= quote validity (rule 1)
- Constants: MAX_AUDITED_QUOTE_AGE=60m; max_first_audit_delay = per_peer_cooldown(30m)
  + FIRST_AUDIT_RETRY_INTERVAL + AUDIT_TRANSIENT_DEADLINE(2m) + scheduling_slack(5m)
  = 42m; clock_skew_margin=10m. Startup assert (against live config + consts):
  MAX_AUDITED_QUOTE_AGE + max_first_audit_delay + clock_skew_margin <=
  GOSSIP_ANSWERABILITY_TTL (112 <= 180); refuse to boot otherwise.
- confirmation_deadline = quote_ts + MAX_AUDITED_QUOTE_AGE + max_first_audit_delay
  + clock_skew_margin, from the accused's SIGNED quote_ts (never the auditor clock).
- Node-side freshness gate: reject at fresh-put payment any above-baseline
  quote/candidate whose signed quote_ts is outside [now-window-skew, now+skew]
  (single AND merkle; baseline (0,None) exempt). Future-dated quotes rejected.
- First-audit scheduling governs COVERAGE not SOUNDNESS: a challenge issued after
  confirmation_deadline is skipped/graced, so an overloaded scheduler misses a
  conviction but never causes a false one (capacity alarm on overload).

## Conviction scope (the decision)
- Convict only definitive responses (UnknownCommitment / missing / wrong bytes)
  from a RESPONSIVE node, for source==PaidQuote && sidecar_present && challenge
  issued at-or-before confirmation_deadline. Auditor grades from its OWN persisted
  admitted record.
- Non-response (timeout/bootstrap/persistent-transient): NOT convicted here ->
  existing ADR-0002 timeout lane; add a targeted revocation of stale holder
  credit for an admitted paid pin on non-response (today Timeout/Bootstrapping
  keep credit). Full eviction stays behind the TIMEOUT_EVICTION gate (bounded
  exposure until enabled).
- Credit-revocation retained + scoped for all graced/non-response paths; only
  superseded (direct penalty) on the confirmed definitive path. Not deleted.
- Portable evidence: signed quote/candidate + quote_ts, canonical signed
  commitment bytes, derived pin/root, payment_id (on-chain settlement keyed by
  the signed quote hash), auditor's SIGNED challenge (ts+nonce+id), responder
  RejectKind/bad bytes, verifier transcript. Third parties reject a conviction
  whose signed challenge time > confirmation_deadline.

## Identity / merkle
- Per quote form: single-node (peer, commitment_pin); merkle PER accepted
  candidate (peer, candidate.commitment_pin) with the candidate's own signed
  quote_ts/sidecar. No batch-level pin; one stale/no-sidecar candidate is rejected
  on its own slot.
- Quote/candidate signature binds {price, peer/rewards, quote_ts,
  committed_key_count, commitment_pin, sidecar hash} (all known at sign time);
  payment_id = on-chain settlement keyed by the signed quote hash, bound at
  ingestion. Sidecar mandatory for every above-baseline quote in a fresh bundle;
  gossip-only pins never upgraded to paid-confirmed.

## Admission cap
- Admission-only: never evict a live entry before its deadline; a full ledger
  stops new above-baseline quote emission (backpressure).

## Out of scope / not a backstop
- Possession-check lane is NOT part of this soundness argument (per-chunk,
  checker-dependent, timing-bypassable).

## Code touch points
- src/replication/storage_commitment_audit.rs: dispatch_subtree_response,
  request_byte_proof (thread paid provenance/deadline + apply the override; keep
  is_graced() for non-paid).
- src/replication/commitment_state.rs: persisted paid-pin ledger + recovery;
  lookup_by_hash paid dominance.
- src/replication/mod.rs / pruner: provenance-scoped is_held veto.
- src/payment/verifier.rs + quote path: node-side freshness gate + startup assert.
