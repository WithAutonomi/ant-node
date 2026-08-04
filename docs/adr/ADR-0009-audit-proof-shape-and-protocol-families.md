# ADR-0009: Subtree-audit proof shape and protocol family

- **Status:** Proposed
- **Date:** 2026-07-29
- **Decision owners:** Anselme (@grumbach)
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0002 (gossip-triggered contiguous-subtree audit), ant-node #181, V2-685

## Context

ADR-0002 records a gossip-triggered subtree audit whose second round returns the
audited chunks' original bytes. Fleet measurement showed that response to be one
of the largest steady-state replication traffic sources: on a same-network
control cohort the mean response was 6.19 MB, and production sampling agreed at
5.79 to 6.15 MB across four separate days. The cost is paid per audit event
regardless of how often audits fire, so frequency caps alone cannot bound it.

The V2-685 change is intentionally scoped to this subtree audit. The core
replication protocol also carries the periodic responsible-chunk audit, the
post-replication possession probe, and prune-confirmation challenges through the
existing `AuditChallenge`/`AuditResponse` pair. Their wire format, digest
construction, timeout accounting, and protocol id are not changed by this
decision.

ADR-0002 is not amended. It records what was decided then; this ADR records the
replacement for the subtree audit's round-2 proof shape and the wire isolation
needed to roll that replacement out.

## Decision Drivers

- Reduce subtree round-2 egress from whole chunks to bounded verified slices.
- Preserve the security-relevant binding between round 1 and the bytes opened in
  round 2.
- Keep core replication and its digest-audit lanes interoperable throughout a
  mixed-version rollout.
- Bound subtree responder CPU, disk, memory, and pre-admission decode work.
- Avoid changing unrelated replication, possession, and pruning behavior.

## Considered Options

1. Keep full-chunk subtree round-2 responses and rely on frequency caps.
2. Replace subtree round 2 with verified slices and give the changed subtree
   message family a dedicated protocol id.
3. Replace subtree round 2 with verified slices and advance the shared core
   replication protocol id.

## Decision

We take option 2.

### Round-2 proof shape

A chunk's address is its BLAKE3 root, and BLAKE3 is internally a Merkle tree over
1 KiB blocks. The responder therefore returns a verified slice for an opened
block rather than the entire chunk.

Because the public chunk address proves authenticity but not fresh possession,
round 1 additionally commits a per-leaf nonced block-tree root over the same
blocks. Round 2 verifies both the Bao address proof and the nonced-tree opening
against the same block bytes. The auditor draws the block after receiving the
round-1 commitment and anchors the claimed content length against the address.

The subtree-specific key derivation uses a versioned BLAKE3 `derive_key`
context over the nonce, challenged peer, and chunk key. This construction belongs
to the subtree proof only; it does not replace the digest helper used by the core
responsible, possession, or pruning lanes.

### Protocol family

Core replication keeps `autonomi.ant.replication.v2`. The four subtree bodies
(round-one challenge/response and round-two slice challenge/response) ride
`autonomi.ant.replication.subtree-audit.v1`.

Inbound dispatch accepts the core and subtree ids in both bare and
request-response forms. A symmetric body/id guard accepts subtree bodies only on
the subtree id and every other replication body—including
`AuditChallenge`/`AuditResponse`—only on the core id. Responses use the same
mapping.

This isolates the wire-incompatible subtree proof without partitioning fresh
replication, neighbour sync, fetch, repair, verification, responsible audits,
post-replication possession probes, or prune confirmation.

### Unanswered round 2

Because round 2 names blocks only after the round-1 roots have been committed, a
responder learns the draw before deciding whether to reply. An unanswered round
2 following a valid round-1 proof revokes the holder credit associated with the
commitment under audit. It remains in the subtree audit's existing graced timeout
lane: ordinary reply loss is not a confirmed integrity failure, but the peer
cannot retain proof-derived credit without completing possession checks.

This subtree timeout rule does not alter timeout penalties in any core
digest-audit lane.

### Responder work bounds

Round 1 selects a fixed-depth block of the commitment tree sized to about the
square root of the key count, so the nonce cannot steer the responder into
reading its entire store. It has:

- A small dedicated global admission pool.
- A one-request-per-peer concurrency limit and responder cooldown.
- Hashing work off the async executor.
- A responder-wide byte budget that cannot be bypassed by rotating peer ids.
- A single-use, TTL-bounded round-one session required for round two.

The work budget carries debt, so an expensive proof is admitted proportionally
less often than a cheap one. Its refill and burst sizes are set above measured
honest demand at the maximum supported commitment size.

### Wire and decode bounds

Subtree family messages take a tighter wire ceiling than core replication. The
limit is selected from the encoded body discriminant before deserializing
attacker-controlled collections and is sized above the largest legitimate
round-one proof at the commitment key-count cap.

Core messages retain the existing core ceiling. In particular,
`AuditChallenge` and `AuditResponse` remain core messages and are not
reclassified by this ADR.

## Consequences

### Positive

- Round-2 subtree responses fall from megabytes to kilobytes. A 990-node run
  measured 14.49 KB over 69,903 responses against 6.19 MB on a simultaneous
  same-network control cohort, about a 427x reduction in decimal units.
- Subtree egress per audit event becomes bounded independently of audit cadence.
- Core replication and all existing digest-audit lanes retain their behavior and
  wire compatibility.
- A mixed-version subtree exchange cannot be misdecoded as a core message.
- Heavy round-one work and round-two access are bounded independently from the
  core replication responder path.

### Negative / Trade-offs

- Round 2 samples blocks rather than returning a whole chunk. A peer retaining a
  fraction `p` of a chunk's blocks can pass when every draw lands on retained
  blocks, roughly `p^leaves` for the configured 3..=5 sampled leaves. The final
  block anchors length but does not add random detection. Repeated sampling and
  the much lower per-audit cost are the compensating mechanisms.
- The proof is delegable. All challenge inputs are public, so a backend holding
  one copy can compute roots and openings for multiple front-end identities. The
  previous full-byte response was also delegable but imposed much higher relay
  egress. Fixing non-delegability requires peer-specific encoding at rest or an
  economic mechanism outside this proof.
- Cross-version subtree audits pause during rollout because their proof shapes
  are incompatible. Core replication and core digest audits do not pause.
  Unanswered subtree requests may still incur the transport layer's ordinary
  liveness accounting.
- The replication subsystem has two protocol ids instead of one.
- Recently proved holder credit cannot be refreshed across the subtree version
  boundary. Once existing credit expires, cross-version claims are treated
  conservatively as unproven until both sides run the new subtree audit.

### Neutral / Operational

- Existing traffic-counter field names for round-two responses are retained so
  before/after fleet measurements remain comparable.
- The subtree protocol can be versioned independently from core replication.
- Round-one concurrency and cooldown are configurable for testnet tuning.

## Validation

- Unit tests pin Bao slice authenticity, nonced opening verification, content
  length anchoring, canonical geometry, session use, and work-budget accounting.
- Attack proof-of-concept tests cover fabrication, substitution, replay,
  under-storage, malformed proofs, and resource-bound bypass attempts.
- Real-QUIC end-to-end tests cover honest subtree audits, data-deleting nodes,
  repeated audits without false positives, and protocol-family isolation.
- Routing tests assert that subtree bodies are accepted only on the subtree id
  while core and digest-audit bodies remain on the core id.
- Size tests prove the largest legitimate subtree response fits its ceiling and
  oversized subtree collections are rejected before allocation.
- Re-validation is required for changes to subtree key derivation, sampling,
  round-one selection, session rules, or the subtree protocol family.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human
review**. Accepted ADRs are immutable: create a new superseding ADR rather than
editing an Accepted ADR.
