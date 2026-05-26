# Testnet Plan: Storage-Bound Audit (v12 phase-2 foundation)

**Status:** Ready for execution after phase 3 integration lands.
**Branch:** `grumbach/storage-commitment-audit`
**Design:** `notes/security-findings-2026-05-22/proposal-gossip-audit-v12.md`

## What's deployable today

Phase 1 + 2 of the v12 design are merged on this branch:

- `src/replication/commitment.rs` — wire types (`StorageCommitment`,
  `CommitmentBoundResult`), Merkle tree, ML-DSA-65 signing, commitment
  hash, path verification.
- `src/replication/commitment_state.rs` — `BuiltCommitment` +
  `ResponderCommitmentState` with two-slot retention; responder-side
  `build_commitment_bound_audit_response`.
- `src/replication/commitment_audit.rs` — pure
  `verify_commitment_bound_response` with 4 gates (structural / peer-
  identity / pin + signature / per-key bytes+path+digest).
- `src/replication/recent_provers.rs` — bounded per-key cache of
  recent provers; hash-bound credit predicate.
- Tests: 22 + 12 + 13 + 9 in the four modules + 17 PoC tests in
  `tests/poc_commitment_audit_attacks.rs`. 549/549 pre-existing lib
  tests still pass.

**These pieces stand alone and are codex-APPROVED across all rounds.**

## What's NOT yet deployable (phase 3)

The phase-2 modules are not yet wired into the live replication loop:

- Responder doesn't yet build/sign/cache a commitment on a tick.
- Responder doesn't yet piggyback the commitment on outbound
  `NeighborSyncRequest`/`Response`.
- Auditor doesn't yet store `last_commitment` per RT peer on gossip
  receive.
- Auditor doesn't yet issue `expected_commitment_hash` in challenges.
- Auditor doesn't yet handle the `CommitmentBound` response variant.
- Holder-eligibility (`recent_provers.is_credited_holder`) doesn't yet
  gate quorum / paid-list / reward decisions.
- Wire-type extension (Option fields on existing structs) reverted
  pending phase-3 protocol-version decision (postcard isn't
  bidirectionally forward-compatible via `#[serde(default)]` alone).

A live testnet validating the design end-to-end requires phase 3.

## Phase 3 wiring — TODO before testnet

| Component | What to add | File |
|---|---|---|
| Wire extension | Protocol-version bump or new `CommitmentAnnounce` `ReplicationMessageBody` variant | `protocol.rs` |
| Responder tick | Rebuild Merkle + sign + rotate every commit-debounce interval (~5-15 min) | `mod.rs` |
| Responder gossip | Set `commitment: Some(...)` on outbound NeighborSync | `neighbor_sync.rs` |
| Gossip receive | Verify + store `last_commitment` per peer; rate-limit per peer | `mod.rs` |
| Audit issue | Set `expected_commitment_hash` from per-peer `last_commitment` | `audit.rs` |
| Audit response | `CommitmentBound` variant: call `verify_commitment_bound_response`; record into `recent_provers` | `audit.rs` |
| `UnknownCommitmentHash` handler | v12 §5 conditional invalidation: clear `last_commitment[P]` only if stored hash still equals rejected pin | `audit.rs` |
| Holder eligibility | Quorum / paid-list / repair-proof gating reads `recent_provers.is_credited_holder` for commitment-capable peers | `quorum.rs`, `paid_list.rs` |

## Testnet deployment plan

### Pre-deployment checklist

- [ ] Phase 3 wiring complete and codex-approved.
- [ ] All threat-model PoC tests still pass against the wired build.
- [ ] One round of `cfd` + full lib + e2e on `main`.
- [ ] An RC branch cut from `grumbach/storage-commitment-audit` after
      rebase onto latest main.
- [ ] Mick + Chris one-pass code review.
- [ ] David sign-off.

### Fleet topology

Use the existing 9-VPS production-shape testnet (per
`docs/infrastructure/INFRASTRUCTURE.md`):

- 6 bootstrap nodes across DigitalOcean / Hetzner / Vultr (3 regions, 2 each).
- 3 application nodes for upload load.
- All nodes on the project's UDP port range 10000-10999 (per project CLAUDE.md).
- Sample fleet size: scale to ~30 nodes × 15 services = 450 services
  (matches Chris's DEV-01/DEV-02 musl-soak setup in PR #112).

### Phased rollout

**Stage 0 — single-node smoke (1h):**
Run one node from the branch on an isolated devnet. Trigger 1k chunk
uploads. Confirm:
- Commitment builds + signs on rotation tick.
- Gossip emits the commitment.
- Audit cycles issue commitment-bound challenges.
- Responses verify cleanly.
- No regressions in existing audit / quorum / paid-list paths.
- Logs show expected counter movement.

**Stage 1 — informational mode (24h):**
Deploy to the full testnet but configure `require_commitment_proof =
false` everywhere — gossip emits commitments, auditor stores them, but
audit challenges still use the legacy plain-digest path. Confirm:
- Every peer observes every other peer's commitment within ~3 gossip
  cycles.
- `last_commitment` per peer is populated and refreshes correctly.
- No memory growth beyond the design's ~1.3 MB / 10k keys ceiling.
- No CPU spike from ML-DSA-65 verifies (target: <1% mean CPU per node).
- No protocol regressions: chunk PUT, chunk GET, audit pass rates
  match baseline within ±2%.

**Stage 2 — enforcement (72h):**
Flip `require_commitment_proof = true` for peers that have gossiped a
commitment. Confirm:
- Commitment-bound audits succeed at the expected rate (target: ≥99%
  honest pass rate, matching today's plain-digest pass rate).
- No false-positive `AuditFailureReason::PathInvalid` /
  `BytesHashMismatch` / `DigestMismatch` / `SenderPeerIdMismatch` —
  these mean a bug in our wiring, not a real attack.
- `recent_provers` cache size stays bounded at the documented
  `keys × MAX_PROVERS_PER_KEY × ~80 bytes` ceiling.
- Rotation events (commit recompute) handled without false-failure on
  the boundary — the two-slot retention should absorb cross-rotation
  audits transparently.

**Stage 3 — adversarial smoke (24h):**
Inject a deliberately-buggy responder on one node:
- (a) Always returns `Rejected { UnknownCommitmentHash }` for half its
  responses. Expect: those audits fall back to legacy plain-digest
  (during phase-3 transition) or are recorded as failures (phase-3
  conditional-invalidation handler).
- (b) Returns valid responses but with random bytes for one key.
  Expect: `BytesHashMismatch` / `PathInvalid` recorded; full per-key
  penalty.
- (c) Substitutes another peer's commitment (lifted from gossip).
  Expect: gate 2a `SenderPeerIdMismatch`.

The injection points are not in production code — script it as a debug
override that flips on for a specific node.

### Metrics to collect

Throughout all stages, emit to the existing canary / log pipeline:

| Metric | Target | Alert threshold |
|---|---|---|
| Commitment build time (per rotation) | < 100 ms @ 10k keys | > 1 s |
| Commitment sign time | < 50 ms | > 500 ms |
| Audit verify time (per response) | < 10 ms @ 100 keys | > 100 ms |
| Audit pass rate (honest peers) | ≥ 99% | < 95% |
| Audit fail rate (gate 2a / pin / signature) | 0% in stage 1+2 | > 0.1% |
| `recent_provers` total entries | < 100 MB total | > 500 MB |
| Gossip CPU overhead (ML-DSA-65 verify) | < 1% mean | > 5% |
| Memory growth over 72h soak | flat (allocator-governed) | growing |

### Success criteria

Stage 2 passes if:
- Audit pass rate within ±2% of pre-deployment baseline.
- Zero unexplained audit failures from the new gates.
- Memory + CPU within targets above.
- No regressions in chunk PUT / GET / pruning / paid-list flows.

Stage 3 passes if:
- All three deliberate-bug injections produce the expected failure
  classification (not the wrong one).
- Trust events fire at the expected weight per v12 §6.

### Failure modes to watch

1. **Cross-rotation false-failure**: an honest peer rotates between
   auditor's gossip-receive and challenge-issue. v12 §4 two-slot
   retention should absorb this. If we see real false-failures here,
   either rotation cadence is too aggressive or retention isn't wired
   correctly.

2. **`SenderPeerIdMismatch` false-positive**: should be zero in honest
   traffic. If we see any, it means a peer-id-binding bug somewhere
   else in the stack.

3. **`UnknownCommitmentHash` flood**: if many peers' responses return
   this during stage 2, gossip propagation is slower than audit
   cadence. Tune one of: gossip interval, audit interval, retention.

4. **Memory growth beyond targets**: the `recent_provers` cache or the
   two-slot retention is not freeing entries on the documented
   schedule.

## Post-testnet decision points

1. Tune `MAX_PROVERS_PER_KEY` if the cache pressure is significantly
   over or under the target.
2. Decide whether `commitment_capable = false` peers (those who never
   gossip a commitment, possibly old-version) should be soft-excluded
   from reward credit immediately or after a grace period.
3. Decide on Stage 1 → Stage 2 cutover mechanism for the live mainnet
   (config rollout vs observed-ratio threshold).

## Rollback plan

The phase-3 wiring should be feature-flagged. If stage 2 reveals a
material problem:

1. Flip `require_commitment_proof = false` everywhere via config push.
2. Audits revert to legacy plain-digest (which is unchanged in phase 2
   except for the modules added).
3. Holder credit reverts to today's behaviour (everyone in close-group
   gets credit if quorum passes).

The wire-type extension is the only piece that's hard to roll back
(once peers see the new field on the wire, you can't take it away
without a coordinated downgrade). Hence the protocol-version-bump
recommendation in phase 3 — it gives an explicit kill switch.

## Reporting

Each stage produces a report with:
- Start/end times.
- Fleet topology (nodes per region).
- Metrics tables.
- Any unexpected failures classified by `AuditVerifyError` variant.
- Verdict: pass / fail / inconclusive.

Reports go in `notes/testnet-runs/storage-commitment-audit-stageN.md`.

## Owner

Anselme. Coordinate with Mick (replication review), Chris (release +
testnet ops), David (sign-off).
