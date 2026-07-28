# ADR-0007: Audit proof shape and protocol families

- **Status:** Proposed
- **Date:** 2026-07-28
- **Decision owners:** Anselme (@grumbach)
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0002 (gossip-triggered contiguous-subtree audit), ADR-0003 (possession verification)

## Context

ADR-0002 recorded the gossip-triggered subtree audit with a round 2 that returns
the audited chunks' original bytes. Fleet measurement showed that round-2
response to be one of the largest steady-state replication traffic sources: on a
same-network control cohort the mean response was 6.19 MB, and production
sampling agreed at 5.79 to 6.15 MB across four separate days. The cost is paid
per audit event regardless of how often audits fire, so frequency caps alone
cannot bound it.

Separately, the node has three audit lanes that each ask a peer to prove it holds
specific bytes:

1. the subtree storage-commitment audit (ADR-0002),
2. the post-replication possession probe (ADR-0003),
3. the prune-confirmation audit.

Lanes 2 and 3 share one wire message pair with lane 2's digest helper. Lane 1
built its own per-leaf commitment. The three lanes did not derive their
per-audit freshness the same way, which meant a change to one left the others on
a different footing. Keeping three different answers to the same question is a
maintenance and review hazard independent of any single lane's strength.

ADR-0002 is not amended by this decision. It records what was decided then; this
ADR records what replaces its round-2 proof shape and how the freshness
derivation is unified.

## Decision Drivers

- Egress reduction is the primary goal; the audit must stop moving whole chunks
  to prove they exist.
- One freshness construction across all audit lanes, not three.
- A mixed-version fleet must keep replicating during the auto-upgrade window.
  Partitioning core replication to ship an audit change is too blunt.
- A version skew must never be scored as a peer's fault.

## Considered Options

1. Keep full-chunk round-2 responses and rely on frequency caps alone.
2. Return a verified slice for round 2, and leave the other lanes as they were.
3. Return a verified slice for round 2, unify the freshness derivation across all
   three lanes, and give each changed message family its own protocol id.
4. As option 3, but advance the single shared replication protocol id instead of
   introducing per-family ids.

## Decision

We will take option 3.

**Round-2 proof shape.** A chunk's address is its BLAKE3 root, and BLAKE3 is
internally a Merkle tree over 1 KiB blocks, so the responder returns a verified
slice for an opened block rather than the chunk. Because the address is public,
authenticity alone would not show possession, so round 1 additionally commits a
per-leaf root over the same blocks derived from the fresh per-audit nonce, and
round 2 checks both chains over the same block bytes. The block to open is drawn
with fresh randomness after the round-1 commitment arrives. The auditor also
anchors the responder's claimed content length against the address rather than
trusting it.

**Freshness derivation.** All three lanes derive their per-audit freshness the
same way: the challenge material (nonce, challenged peer, key) is used to derive
a BLAKE3 key under a versioned domain-separation context, and the content is
hashed under that key. Deriving a key rather than prefixing the challenge means
the whole proof depends on the fresh nonce rather than only its leading bytes.

**Protocol families.** Core replication keeps its existing id. The subtree audit
rides its own id, and the digest-based possession audits (lanes 2 and 3, one
shared message pair) ride a second one. A symmetric guard drops any message whose
family disagrees with the id it arrived on.

**Round-1 work bounds.** A single round-1 challenge selects a fixed-depth block
of the commitment tree sized to about the square root of the key count, so the
nonce cannot steer a responder into reading its whole store. Round 1 has its own
small admission pool, a per-peer responder cooldown, and its hashing runs off the
async executor. Round 2 is bound to a single-use session opened by a matching
round 1 from the same peer.

## Consequences

### Positive

- Round-2 responses fall from megabytes to kilobytes. A 990-node run measured
  14.49 KB over 69,903 responses against 6.19 MB on a simultaneous same-network
  control cohort.
- The cost per audit event is bounded regardless of audit rate, which frequency
  caps cannot achieve on their own.
- One freshness construction across all three lanes instead of three.
- Core replication is not partitioned by an audit change. A mixed-version run
  measured 736/736 and 135/135 transfers with no failures, and the older cohort
  continued to accept and store paid chunks throughout.
- A version skew on an audit lane produces no answer rather than a wrong answer,
  so it lands in the timeout lane instead of the confirmed-failure lane. The
  subtree lane already graces timeouts. The three digest lanes did not — they
  reported a confirmed-failure trust event on a timeout — so a temporary rollout
  gate (`GRACE_POSSESSION_AUDIT_TIMEOUTS`) graces them for the upgrade window.
  See the trade-offs below: that gate must be removed in a follow-up.

### Negative / Trade-offs

- Round 2 now proves a sampled block rather than a whole chunk, so per-response
  coverage is narrower and the guarantee rests on repeated sampling over time.
  Stated precisely, because it is the load-bearing trade-off: the auditor holds
  none of the audited bytes, so it cannot distinguish a correct nonced root from
  a responder-chosen one. A peer retaining a fraction `p` of a chunk's blocks can
  commit a root with genuine leaves for what it kept and arbitrary leaves for
  what it dropped, and passes whenever every draw lands on a kept block —
  roughly `p^leaves` per audit over the 3..=5 sampled leaves. The mandatory
  final-block opening anchors the claimed length but adds no detection, since a
  partial holder keeps the final block. The full-byte round 2 this replaces
  caught any missing byte of a sampled chunk with certainty.

  The exchange is deliberate, and the comparison should be stated in both
  directions. Against a node under-storing **in bulk** — the realistic case, a
  node dropping data to save disk — detection is close to what the full-byte
  audit gave, at roughly a thousandth of the egress; the fleet run caught a
  256 MB in-place corruption on the first audit that reached the node, by three
  independent auditors, against zero false positives across ~43,000 audits in
  the preceding 5.5 hours. Against a **fine-grained** partial deleter, one
  shaving a little off every chunk, it is strictly weaker per audit than serving
  every byte. The compensating lever is audit *frequency*, which is what the cost
  reduction buys: the old shape made frequent auditing unaffordable. If a future
  threat model needs sharper per-audit detection, the knob is openings per leaf,
  at linear egress cost.
- Three protocol ids to reason about instead of one.
- A temporary rollout gate (`GRACE_POSSESSION_AUDIT_TIMEOUTS`) suppresses the
  timeout penalty on the three digest lanes so a version skew cannot punish an
  honest peer at confirmed-failure weight for the upgrade window. While it is
  set, a peer that silently drops audit challenges is under-penalised: it still
  takes the upstream unit transport decrement, but not the audit-severity one.
  **This must be turned off and deleted in a follow-up once the fleet has
  upgraded.** The guarded branches stay compiled rather than commented out so
  they cannot rot while disabled.
- Cross-version audits pause during the auto-upgrade window. Unanswered requests
  still register a unit trust decrement upstream, which decays back to neutral;
  the possession lanes probe more often than the subtree lane, so their dip is
  larger. This is milder than either a stream of confirmed failures or a fleet
  wide replication partition, but it is not zero.
- The responsible-chunk audit now returns no verdict when it cannot check a
  challenged key against its own copy, so some ticks that previously recorded a
  pass now record nothing.

### Neutral / Operational

- The wire counter for the round-2 response keeps its original name so the
  measurement is directly comparable across versions.
- Each protocol family can be versioned independently from here on.

## Validation

- Focused unit tests pin the proof construction, the freshness derivation, the
  canonical proof geometry, and the length anchoring.
- Attack proof-of-concept suites cover fabrication, substitution, replay, and
  data-deletion behaviour against the responder.
- A real-QUIC multi-node end-to-end test covers an honest node passing, a
  data-deleting node being caught, and repeated audits producing no false
  positives.
- Routing tests assert that each message family is accepted only on its own
  protocol id, in both directions.
- Fleet evidence: response size against a same-network control cohort,
  detection parity, false-positive rate, mixed-version transfer success,
  round-1 CPU and memory against baseline, and node stability.
- Re-validation trigger: any change to the freshness derivation, the sampling
  rule, the round-1 selection bound, or the set of protocol families.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human
review**. Accepted ADRs are immutable: create a new superseding ADR rather than
editing an Accepted ADR.
