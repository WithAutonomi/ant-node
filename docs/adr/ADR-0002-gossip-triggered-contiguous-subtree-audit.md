# ADR-0002: Gossip-triggered contiguous-subtree storage audit

- **Status:** Proposed
- **Date:** 2026-06-04
- **Decision owners:** Anselme (@grumbach)
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** none

## Context

In this network, nodes are paid to store data chunks. To verify a node actually
holds what it is paid for, each node publishes a signed **storage commitment**: a
Merkle tree built over the chunks it claims to hold (one leaf per chunk, the leaf
being a hash of the chunk's content which incidentally also is its address on the network), reduced to a single root hash and signed by
the node's key. The commitment is spread to neighbouring nodes through the
network's normal periodic message exchange ("gossip"). Any neighbour can then choose to
**audit** the node: ask it to prove it still holds the committed chunks, sampled
probabilistically so that no single audit is expensive but cheating is caught over time.

Triggered by gossip, the audits run as occasional surprise
exams, with no answer that escapes accounting, every failure is attributable to misbehaviour, including failure to respond in a reasonable time. 

### Relationship to the responsible-chunk audit

This ADR covers the **storage-commitment audit**: it proves a node still holds
the data it *claims* to hold (the chunks in its own signed commitment) — i.e. it
catches deletion and on-demand relaying of committed data. It does **not** replace
the pre-existing **responsible-chunk audit**, which proves a node holds the data
it *should* hold: a node samples keys a close peer is responsible for (and was
previously hinted to store) and challenges the peer to produce per-key possession
digests. The two are complementary and run side by side — the storage-commitment
audit is gossip-triggered (no timer of its own), while the responsible-chunk audit
keeps its own periodic tick. Each has independent accounting; this ADR's
adaptive-grace and rollout gating apply to the storage-commitment audit only.

Terms used below: *root* = the single top hash of a node's storage-commitment
Merkle tree. *Leaf* = the hash of one stored chunk. *N* = the number of chunks a
node has committed to. *Subtree* = a contiguous branch of the tree (a node in the
tree plus everything beneath it). *Padding* = empty filler leaves added so the
tree is a clean binary shape when N is not a power of two.

## Decision Drivers

- Ensure all nodes actually store the data they claim they are storing
- Keep each proof small and keep steady-state audit traffic low.
- Catch the three real cheating strategies: storing nothing and fetching on demand; deleting some fraction of data; and keeping only chunk *addresses* (which are public) while never holding the actual bytes, then fabricating proofs.
- Reuse the existing cryptographic building blocks (the Merkle tree, the signed commitment, the freshness hash) without inventing new ones.
- Never wrongly penalise honest nodes, even in extreme cases like on small or dense networks where every node legitimately holds almost all of the data.

## Considered Options

1. **Keep the previous timer-driven schedule and just make the excusable answers
   punishable.** Rejected: an audit answer like "I don't recognise that commitment"
   was excusable *precisely because* the audited commitment was stale relative to
   what the node had since published. Without fixing the schedule, punishing such
   answers would also punish honest nodes whose latest commitment simply hadn't
   propagated yet.

2. **Keep naming individual chunks to audit, but trigger the audit from gossip.**
   A better trigger, but it keeps the large, scattered proof (a separate inclusion
   path per sampled chunk) and the "auditor names the chunks" model, which lets a
   node honestly answer "that chunk isn't in my commitment" — another answer that
   has to be excused.

3. **Gossip-triggered, single contiguous-subtree proof (chosen).** Receiving a
   node's commitment is what may launch an audit, checked against that freshly
   published commitment. A random value chosen by the auditor deterministically
   selects one contiguous branch of the audited node's *own* tree; the node returns
   that whole branch plus a small summary of the rest; the auditor rebuilds the
   root, spot-checks a few leaves against real chunk bytes, and requires a timely
   response. Small proof, no excusable answers, surprises the node.

4. **Select several branches per audit instead of one.** Rejected: against an
   attacker who deletes data in large contiguous blocks, the per-audit chance of
   catching them depends only on the *fraction* deleted, not on how many or how
   large the branches are. Extra branches only add proof cost; a fresh random
   selection each audit covers the tree over time anyway.

## Decision

We will make the audit **gossip-triggered** and replace its proof shape with a
**single contiguous-subtree storage proof**, reusing the existing tree,
commitment, and freshness-hash primitives.

- **Trigger.** When a node ingests a neighbour's commitment during normal
  (steady-state) operation, it may start an audit of that neighbour — not every
  time, but with a fixed probability and a per-neighbour cooldown, so audits are
  occasional surprise exams that keep traffic low. The decision is cooldown-first
  then the probability lottery, so a burst of gossip from one peer yields at most
  one audit attempt per cooldown window. The audit always checks the neighbour
  against the commitment it *just published*, and a *stable* commitment is still
  re-audited over time (the trigger fires on every steady-state gossip, not only
  on a changed root). This storage-commitment audit has no periodic timer of its
  own; it is driven entirely by gossip and runs **alongside** the separate
  responsible-chunk audit (see "Relationship to the responsible-chunk audit"),
  which keeps its own periodic tick.
  *Exception:* gossip received during the node's own bootstrap is cached but does
  NOT trigger an audit — the node may itself still be bootstrapping (audits are
  gated on that) and its routing-table view is not yet stable. Such a peer is
  audited on the first steady-state gossip round after bootstrap drains (within
  one sync cycle), so there is no coverage gap.

- **Subtree selection.** The auditor sends a fresh random value. That value walks
  the tree from the root downward (each bit picking left or right) and stops at
  the smallest contiguous branch that still contains at least the square root of N
  *real* (non-padding) leaves. Stopping on a real-leaf count — rather than at a
  fixed depth — is deliberate: a fixed depth can, when the tree is mostly padding,
  land on a branch that is entirely padding, so the audit checks nothing. The
  real-leaf rule makes an empty selection impossible. The random value alone fixes
  *which* branch is selected: the auditor and the audited node each walk the tree
  from it independently and arrive at the same branch, so the audited node cannot
  choose a convenient branch to present. The auditor then checks that the returned
  branch is exactly the one the random value selects and that it contains at least
  the square root of the claimed held chunks in real leaves.

- **The proof.** The audited node returns every leaf of the selected subtree —
  each given both as the plain content hash and as a freshness hash (the content
  mixed with the auditor's random value) — plus one summary hash per level for the
  unselected siblings along the path to the root. Everything outside the selected
  branch costs a single hash; nothing there is touched.

- **Verification, three independent checks.**
  - *Structure:* rebuild the root from the returned subtree and the sibling
    summaries; it must equal the freshly-published root the audit was started
    against. This proves the subtree genuinely belongs to the committed tree.
  - *Real bytes:* after the full subtree proof is in hand, pick a small fixed
    number of its leaves and demand the original chunk bytes for exactly those
    keys from the audited node itself (a second-round surprise challenge), then
    confirm both the plain hash (the chunk's content address) and the freshness
    hash match the served bytes. The sample is drawn with **fresh randomness
    chosen by the auditor after round 1 — NOT derived from the round-1 nonce**.
    This is essential: the structural root check binds only `(key, bytes_hash)`,
    both of which are public (the `bytes_hash` *is* the chunk's network address),
    not the per-leaf freshness hash. If the sample were predictable at
    proof-build time, a relay could fabricate the freshness hash on every leaf,
    fetch only the few leaves it knew would be opened, and pass while holding
    almost nothing. Drawing the sample after the proof commits turns this into a
    cut-and-choose: the node must have produced a correct freshness hash — which
    needs the real bytes — for essentially every leaf, or be caught. Possession
    is non-delegable: the auditor needs to hold none of the node's chunks, and a
    committed key the node cannot serve is a deterministic failure, never bad
    luck. So a node that rebuilt the tree from public chunk addresses but never
    held the bytes cannot serve content that hashes to the committed address;
    faking a fraction of leaves survives only with probability (1 − fraction)
    raised to the number of spot-checks.
  - *Possession in time:* the whole response must arrive within a deadline sized
    to hashing the subtree from local disk. A node that doesn't hold the data must
    fetch it across the network first and misses the deadline.

- **Retention — "you stay answerable for what you publish."** A node keeps the
  chunk data behind its **last two published commitments**. Two, not one, absorbs
  the normal race where an auditor is asking about the commitment a node published
  just before its newest one. Because of this, an honest node can always answer an
  audit about a commitment it published recently — so "I don't recognise that
  commitment" about a recently-published root is now provably misbehaviour, not
  lag.

- **Accounting and False Positives** "That chunk isn't in my commitment" 
  can never occur, because the auditor only ever challenges leaves of the node's
  *own* committed tree, so every challenged leaf is in the commitment by
  construction. Failures that are deterministic and cannot be caused by bad luck — a
  rebuilt root that doesn't match, a content or freshness hash that doesn't match,
  or repudiating a recently-published commitment — are acted on **the first time
  they occur**, because re-asking cannot turn a genuine failure into a pass.
  Failures that *can* be caused by transient bad luck — a missed response deadline
  — keep a small grace allowance of consecutive misses (reset on any success)
  before counting, so a momentarily slow but honest node is not punished. This
  grace allowance is the *only* failure type that the adaptive scaling below
  touches; deterministic failures are always acted on the first time, regardless
  of network conditions.

- **Closeness** A node should mostly hold chunks whose addresses are
  near its own. We may flag a selected leaf as suspicious padding only when its
  address is implausibly far from the node *relative to how much data overlap is
  normal on this network*. On a small, dense network where every node holds nearly
  everything, "far" chunks are normal and must never trigger a penalty. This check
  is intentionally biased toward missing some padding rather than ever wrongly
  penalising an honest node.

- **Network Resilience** In the event of large churn or generalized network
  disruption, to prevent a death spiral, the **timeout** grace allowance (and only
  that allowance) scales with how widely *timeouts* are currently being seen: the
  number of consecutive deadline misses tolerated is the median recent *timeout*
  count across recently-audited peers plus a constant (in a healthy network this is
  roughly 0 + 3). Crucially, the scaling is driven by missed-deadline / liveness
  signals — never by deterministic failures (a bad root or a bad hash), which are
  always acted on immediately and can therefore never be inflated by an attacker to
  buy itself more grace. Genuine disruption makes *honest* nodes time out together,
  lifting the median and relaxing the deadline tolerance just when the network is
  struggling; once conditions normalise the median falls back toward zero and the
  tolerance tightens again. Because most nodes are honest, the median sits near
  zero in normal operation, so this never weakens detection of a node that is
  actually deleting data.

## Consequences

### Positive

- The deterministic nature of the 3 checks makes a faked proof detectable: a structurally wrong, byte-less, or stale answer fails outright, and repeated probabilistic sampling catches the cases that can only be hidden in one branch at a time. 
- The probabilistic approach to verification ensures that verification is cheap but over time efficient. 
- Each proof is small and contiguous (about the square root of N leaves plus a handful of summary hashes) instead of many scattered inclusion paths.
- Audits are surprise exams pinned to the *freshly published* commitment, so there is no stale-data ambiguity unlike in the previous audit design
- Three independent defences cover the three cheating strategies: structure (belongs to the committed tree), real bytes (actually held, not fabricated from public addresses), and timeliness (held locally, not fetched on demand).
- Acting on the first deterministic failure roughly cuts time-to-detection compared with requiring several strikes, with no added risk of false positives.

### Negative / Trade-offs

- **Big-block deletion is caught only proportionally.** An attacker who deletes data in large contiguous blocks is caught, per audit, with probability roughly equal to the fraction deleted — independent of N and of subtree size. We accept this: there is no economic reason to delete a *small* fraction (you save almost nothing and are still eventually caught), and a node that deletes a large fraction to actually save resources is caught within one or two audits. If ever needed, the lever is auditing *more often*, not bigger subtrees.
- **Inflating the claimed size is not fully prevented.** Only the selected subtree and the path summaries are verified each audit, so filler leaves elsewhere could inflate the claimed chunk count. Both the regular audits and the closeness check mitigates this over time. Fully auditing the entire claimed set would be too much effort. We accept this probabilistic approach in which over time cheaters are detected. 
- **Retention has a storage cost.** A node must keep the chunk data behind its last two published commitments. This is an accepted cost. 
- **The audit format change is breaking.** The whole network must upgrade before the new audit can be relied on and before eviction is enabled.

### Neutral / Operational

- Introduces a few tunable settings: the per-gossip audit probability, the per-neighbour cooldown, the number of real-byte spot-checks, and the retention count (two). The grace allowance for missed deadlines reuses the existing strike threshold and applies to deadline misses only.
- The storage-commitment audit needs no periodic timer of its own — it is driven by gossip. (The separate responsible-chunk audit keeps its periodic tick; the two run side by side.) The related "node is capable but has no current commitment" special case is unnecessary on the gossip-triggered path, since that path always has a freshly-published commitment to pin. A silent node needs no special handling for this audit — it simply stops earning storage credit, so all nodes are naturally motivated to gossip. 
- At the chosen settings, steady-state audit load is on the order of a handful of small audits per node per hour.

## Validation

How we will know this decision remains correct:

- **Detection holds in simulation.** For deletions spread evenly across a node's
  data, the per-audit chance of catching it rises quickly with the square root of
  N; for deletions concentrated in large contiguous blocks (the worst case), it is
  roughly the deleted fraction per audit. A simulation must confirm both rates and
  that, at the chosen settings, a node deleting a meaningful fraction is caught
  within one or two audits and a worst-case concentrated large deletion within
  about an hour. Detection must not depend on ever sampling the whole tree.

- **Tests required before this ADR is Accepted.** Branch selection is deterministic
  and identical on the auditor and the audited node; selection never lands on an
  all-padding branch across many awkward sizes (a regression test for the
  fixed-depth flaw this ADR fixes); the root rebuilds correctly from a single-branch
  proof; possession verifies from the bytes the audited node itself serves in the
  second-round byte challenge (the auditor holding none of them); a committed key
  the node cannot serve is a deterministic failure; the real-byte spot-check catches a node that fabricated
  freshness hashes, at the expected probability; deterministic failures are acted on
  the first time while deadline misses honour the grace allowance; the adaptive
  timeout grace responds to widespread timeouts but never to deterministic failures;
  repudiating a recently-published commitment fails; the last two published
  commitments stay answerable; the response deadline is sized correctly; and a flood
  of gossip does not multiply audits.

- **Operational signals and re-open triggers.** Audits per node per hour stay within
  budget; false-positive penalties on a small, dense test network stay at zero
  (confirming the closeness leniency and the adaptive grace hold); during induced
  churn the network does not enter an eviction death spiral; revisit the
  concentrated-deletion trade-off if a real attacker is ever observed deleting below
  the economically-irrational threshold; revisit if the maximum supported committed
  size is approached.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human
review**. Accepted ADRs are immutable: create a new superseding ADR rather than
editing an Accepted ADR.
