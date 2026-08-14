# ADR-0010: Settlement version and pre-payment compatibility

- **Status:** Proposed
- **Date:** 2026-08-13
- **Decision owners:** Anselme Grumbach
- **Reviewers:** David Irvine
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0008 (storage economics and payment protocol); ant-protocol#23; ant-node#204; ant-client#171

## Context

ADR-0008 raised the merkle settlement multiplier to 3x. It changed client code and node code and **changed no wire type**, so nothing tied the two together. A client built before the change could still collect quotes, still pay, and only then discover that every storer refused the upload.

That ordering is what makes it expensive. A merkle batch settles on-chain **before any storer sees a PUT**, and merkle receipts are not refundable. So the check that mattered ran after the money was gone. Production has been rejecting a slow trickle of such uploads at an exact 3x shortfall, each one a user's payment destroyed, reported to them as two integers to compare.

ADR-0008 anticipated this and listed it as a re-open trigger: *"a rise in refused batch uploads after the boundary, indicating clients that never upgraded."* This ADR is that trigger being answered.

The general problem is that **`PROTOCOL_VERSION` describes what a peer can parse, and nothing described how a peer settles**. Those two move independently. Every future change to settlement arithmetic reproduces this failure unless something carries the second fact.

## Decision Drivers

- A refusal must land **before** payment. Merkle settlement is irreversible, so after-the-fact verification cannot be the only check.
- A client-first rollout must stay **usable**, though this decision does narrow it. ADR-0008 chose client-first because a client paying more was accepted by an old node for free. Bounding the upper end ends that: an old node now refuses a newer client rather than quoting a payment it cannot promise to honour. The refusal is deliberately not a client fault, so a newer client routes to peers that can serve it and its user sees nothing, but **node rollout becomes a prerequisite for the next settlement bump** rather than merely desirable. That is the price of not paying before compatibility is established, and it is paid knowingly.
- Old peers must not be misread. `ChunkMessage` is postcard-encoded and non-self-describing, so a new field silently changes how existing peers parse every message.
- The user must be told what to do. The failure is only expensive because it is silent.

## Considered Options

1. **Bump `CHUNK_PROTOCOL_ID` to v3.** The established mechanism for wire changes here (ADR-0004, ADR-0005). Clean end state, but a hard cutover: old peers cannot negotiate a stream at all, so they get a handshake failure rather than a diagnosis, and the whole fleet plus all clients must move together.
2. **Append versioned request variants.** No cutover. Existing discriminants are untouched, unknown variants are rejected cleanly, and nodes and clients can move independently.
3. **Move the multiplier into the contract.** Client submits the 1x price, the contract applies the multiplier. This removes the payer's ability to get it wrong at all, and is the only option that protects clients which never upgrade. Requires a contract upgrade.
4. **Do nothing; drive client adoption.** Cheapest, and closes the *current* burn faster than any of the above. Does nothing for the next settlement change.

## Decision

We will adopt **option 2**, and treat **option 3 as the eventual structural fix** rather than a competing one.

A `settlement_version` travels in the quote request. It is a separate constant from `PROTOCOL_VERSION` and is bumped whenever a change makes an older client pay an amount storers will refuse.

### The compatibility rule

A storer quotes only when the client's version falls inside its own inclusive range:

```
MIN_SUPPORTED_SETTLEMENT_VERSION <= client_version <= CURRENT_SETTLEMENT_VERSION
```

**Both ends are bounded, and the upper bound is the part that is easy to get wrong.** An earlier revision of this work accepted everything at or above the minimum, reasoning that a storer verifies whatever payment actually arrives, so letting a newer client through weakens nothing. That is true only when a settlement change *raises* what is paid. ADR-0008's 3x cleared an old node's 1x minimum, so old nodes accepted new clients for free, and that special case was mistaken for the general rule. A change that redefines the median rule, or which field the contract pays from, produces a payment an older verifier rejects, after the client has already settled.

### Two refusals, not one

The two out-of-range directions need opposite handling and are therefore separate wire variants.

| Condition | Wire error | Whose problem | Client behaviour |
|---|---|---|---|
| `client_version < MIN` | `ClientUpdateRequired` | the client | **Terminal.** Abort before payment, show the upgrade instruction. |
| `client_version > CURRENT` | `StorerUpdateRequired` | this node | **Skip the peer.** Say nothing to the user; use other storers. |

Collapsing them would either tell up-to-date users to upgrade, or strand new clients whenever the node fleet lags. A lagging fleet is the *normal* state during the client-first rollout ADR-0008 prescribes, so this distinction is what keeps the two ADRs compatible.

If too few peers remain after skipping, the operation fails for lack of quotes. That is the correct outcome: it fails before payment rather than after.

### The legacy fallback, and the rule that retires it

A storer built before the versioned requests cannot decode them and simply never answers. Clients therefore retry each silent peer once in the legacy shape, or nothing would work until the whole fleet had upgraded.

**This is a downgrade path.** Silence is not proof a peer cannot parse the request: a dropped response, packet loss, an overloaded peer, and one deliberately discarding versioned requests are indistinguishable from the client side. So the retry can be provoked, and a provoked retry bypasses the gate.

It is safe **only while no client can be refused on version grounds**, which holds exactly while `MIN_SUPPORTED_SETTLEMENT_VERSION` is the first declarable version. The rule is therefore:

> The unversioned retry must be deleted **before either `MIN_SUPPORTED_SETTLEMENT_VERSION` or `CURRENT_SETTLEMENT_VERSION` is raised.**

Both, not just the minimum. Raising `MIN` creates the too-old refusal; raising `CURRENT` creates the node-behind refusal as soon as any node lags, and the retry routes around that one just as readily.

This is enforced by a compile-time assertion in the client, not by review discipline: raising the minimum while a fallback exists fails the build.

There are **two** independent fallbacks, single-node and merkle. The guard is therefore a single shared constant that each site references, so deleting one path cannot orphan the check for the other. An earlier revision put the assertion beside the merkle path only, which left the single-node retry unguarded while this document claimed otherwise.

### A refusal is a verdict about the client, and needs corroboration

Nothing authenticates a refusal. Acting on one peer's word would let a single hostile or misconfigured storer answer `ClientUpdateRequired` to everything and deny every upload the client attempts, converting an over-query design that tolerates many bad peers into one that tolerates none. So a refusal is believed only once `SETTLEMENT_REFUSAL_QUORUM` distinct peers agree, and a refusal that does not describe this client (wrong echoed version, or a stated minimum this client already meets) is discarded as a bad peer rather than counted.

A genuine incompatibility reaches the threshold immediately, because every peer enforcing the newer rule refuses and a client queries far more than two.

The corroborated verdict is then held **client-wide and sticky**, not in one collector's local state. It concerns this build rather than this upload, so an upload that begins after another has already established it must not proceed to pay, and every payment entry point checks it first.

### A refusal must not depend on who answered first

A refusal is a verdict about the client, not about one peer, so it cannot be treated as one failed response among many. Two things follow, and both were wrong in the first implementation:

- The collector stops **launching** new peers once it has enough quotes, but keeps **draining** those already launched. Otherwise a refusal still in flight is discarded because faster peers filled the quota, and the upload pays.
- The verdict is recorded outside the collection timeout. The elapsed arm deliberately falls through so quotes from fast peers stay usable, and would otherwise throw away a refusal observed just before the clock ran out.

`StorerUpdateRequired` deliberately does **not** get this treatment. It is not a verdict about the client, so one lagging peer must not abort an upload the rest of the close group can serve.

### Unversioned requests are still served

A storer cannot distinguish a client that settles correctly but predates the version field (ant-core 0.5.1 through 0.6.0) from one that does not. Refusing both would break clients that are behaving, so unversioned requests are served and counted. Nodes log a running total per path under `ant_node::quote::settlement`.

Flipping that to a refusal is a **follow-up**, gated on that count decaying, and should use a dated self-retiring boundary in the style of `MERKLE_PARITY_ENFORCED_FROM_UNIX`.

## Consequences

### Positive

- A settlement change no longer burns an outdated client's money **on the path the gate covers**: the refusal lands at quote time, where it costs nothing. It is a large reduction rather than an elimination, and the two holes are named under trade-offs below. Read this bullet with those.
- The user is told what happened and what to do, in both the quote refusal and the PUT-time underpayment message.
- No protocol cutover. Nodes and clients roll independently.
- The wire discriminants of every pre-existing message and error are pinned by a regression test, so the append-only property this rests on is enforced rather than assumed.

### Negative / Trade-offs

- **It does not fix the current burn.** A client too old to settle correctly is also too old to declare a version, so the gate cannot see the population causing today's rejections. Only the reworded error reaches them. Driving client adoption remains the cheaper and faster remedy for the incident that prompted this.
- **Merkle storers are not exactly the quoted peers.** The gate covers the 16 candidates a client quotes, but the chunk is stored by each chunk's close group, which may include a peer that never quoted, and routing can move that group between quoting and storing. A storer outside the candidate set can still refuse at PUT time, after payment. This narrows the exposure substantially without closing it, and only option 3 closes it fully.
- **A client binary already in the field cannot be reached.** The cutover guard bounds what future builds may do; it does nothing about a released client that still carries the fallback when nodes later raise their minimum. That is inherent to shipping software, and it is the same reason the storer verifies every payment it is actually offered rather than trusting the declared version.
- **A refusal in a later merkle sub-batch arrives after earlier sub-batches have paid.** Batches above `MAX_LEAVES` settle sequentially, so the gate cannot be consulted for sub-batch two before sub-batch one's money is spent. That call still returns its earlier proofs rather than failing: the caller writes the receipt cache only on the success path, so failing would strand a spend that has already settled on-chain, which is the destruction this work exists to prevent. Nothing is lost by returning them, because the verdict is latched client-wide and stops the *next* payment instead.
- **A single upload can still be denied by two colluding peers.** The corroboration threshold trades a lone-peer denial-of-service for a two-peer one. Two is chosen because a genuine incompatibility clears it instantly while a lone attacker cannot; raising it would blunt the real signal, and the failure mode is availability rather than lost funds.
- The fallback costs one probe per silent peer, bounded by `VERSIONED_QUOTE_PROBE_CEILING` and paid once per peer rather than once per request. Before those two bounds it was one full quote timeout on **every** request, which took the merkle E2E suite from ~24 minutes past the 60-minute CI cap. See the validation section.
- Clients declaring a version are refused by nodes that have not upgraded. Harmless today because no node has a lower `CURRENT`, but it makes node rollout a prerequisite for the next settlement bump.

### Neutral / Operational

- Deploy order is **nodes before clients**, since a node on `ant-protocol` 2.3.x cannot decode versioned requests. The fallback makes this a preference rather than a hard gate.
- The unversioned-quote counter is the input to the follow-up decision above.
- The `ant-protocol` change is additive, so it carries a minor semver impact. The version bump itself is left to the release train, not taken in the PR.

## Validation

- **Wire safety.** `appending_v2_variants_leaves_existing_discriminants_untouched` and `client_update_required_is_appended_to_protocol_error` pin the discriminant of every pre-existing message body **and** every pre-existing `ProtocolError`, responses included. An earlier revision pinned only the request half and the endpoints of the error enum, so a reordered response variant would have passed while breaking old peers.
- **Range policy.** `a_newer_settlement_version_is_refused_rather_than_assumed_compatible` pins the upper bound, which is the specific error this ADR corrects.
- **Refusal direction.** `a_newer_settlement_version_is_refused_as_this_nodes_fault` and `the_two_refusals_do_not_blame_the_same_party` pin that a lagging node never reports a client fault.
- **Terminality.** `a_refusal_aborts_quote_collection_instead_of_counting_as_one_bad_peer` pins that a refusal stops collection rather than joining the failure list, which is what would otherwise let the remaining peers form a quorum and pay anyway.
- **Order independence.** `a_refusal_is_recorded_where_the_collection_timeout_cannot_discard_it` and `meeting_the_target_stops_launching_without_stopping_collection`, plus `a_lagging_storer_does_not_populate_the_refusal_slot`. Stated precisely, because it is easy to overclaim: these pin the *mechanism* — that the verdict is stored where the elapsed arm cannot reach it, and that the launch budget stops recruiting at the target. **No test drives a real collection to timeout**, so the end-to-end ordering behaviour is argued from those two pieces rather than observed.
- **Downgrade bound.** The shared compile-time constant referenced from both fallback sites, plus `only_silence_triggers_the_legacy_retry` and `only_silence_is_evidence_worth_caching`. The constant now bounds `CURRENT` as well as `MIN`: raising either opens a refusal the unversioned retry could route around, and an earlier revision guarded only `MIN`.
### Mixed-version validation, and what it found

The new-client-against-old-fleet case has been exercised for real, not simulated. `ant-client`'s merkle E2E suite spawns a 35-node testnet from the **published** `ant-node`, which predates the versioned requests, so the suite is a live mixed-version run: every node logs `Failed to decode message: deserialization failed` for each versioned probe and answers only the unversioned retry.

It passed functionally and **failed on cost**, which is exactly what a unit test could not have shown:

| | Merkle E2E, ubuntu |
|---|---|
| Baseline on `main` | 24–38 min |
| First implementation | exceeded the 60-min CI cap with 4 of 7 tests done |

The cause was that a peer which cannot decode the versioned request never answers, so the client waited the **full** quote timeout before falling back, and paid that on every request rather than once per peer. The suite runs `quote_timeout_secs = 120`, and a merkle pool asks sixteen candidates.

Two changes came out of it, both in the client:

- **Remember the answer.** A peer that fails to answer a versioned request is asked in the legacy shape from then on, so the probe is paid once per peer instead of once per request.
- **Cap the probe.** A capability probe does not need the patience of a real quote, so the versioned attempt is bounded by `VERSIONED_QUOTE_PROBE_CEILING`. Production's 10s timeout is already below it; the ceiling only binds in test configurations.

Cutting a probe short can misjudge a slow but upgraded peer as legacy. The only consequence is a lost version declaration to that peer, because the fallback still obtains a quote, and it cannot matter while no client can be refused on version grounds. By the time it could, the fallback must already be deleted.

**Still outstanding:** the reverse direction, old client against an upgraded node, and a fleet with both. Those need a testnet built from this branch's `ant-node` rather than the published one, which is not available until the coordinated set lands. Also unproven end to end: structured refusal, lost refusal, and send failure against real peers, which are pinned at unit level only.

### Re-open triggers

- The unversioned-quote count failing to decay, which would mean a long tail of clients the gate can never protect and would raise the priority of option 3.
- Any settlement change that is **not** a monotonic increase, which makes the upper bound load-bearing for the first time.
- Evidence of peers selectively dropping versioned requests, which would mean the downgrade path is being probed and the fallback should be retired early.
- A decision to move the multiplier on-chain, which would supersede most of this.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
