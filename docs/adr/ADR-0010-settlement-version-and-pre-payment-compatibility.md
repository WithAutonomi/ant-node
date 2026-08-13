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
- A client-first rollout must stay possible. ADR-0008 chose client-first deliberately, because a client paying more is accepted by an old node for free. Any policy that makes old nodes refuse new clients breaks that ordering.
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

> The unversioned retry must be deleted **before** `MIN_SUPPORTED_SETTLEMENT_VERSION` is ever raised.

This is enforced by a compile-time assertion in the client, not by review discipline: raising the minimum while the fallback exists fails the build.

### Unversioned requests are still served

A storer cannot distinguish a client that settles correctly but predates the version field (ant-core 0.5.1 through 0.6.0) from one that does not. Refusing both would break clients that are behaving, so unversioned requests are served and counted. Nodes log a running total per path under `ant_node::quote::settlement`.

Flipping that to a refusal is a **follow-up**, gated on that count decaying, and should use a dated self-retiring boundary in the style of `MERKLE_PARITY_ENFORCED_FROM_UNIX`.

## Consequences

### Positive

- A settlement change can no longer burn an outdated client's money. The refusal lands at quote time, where it costs nothing.
- The user is told what happened and what to do, in both the quote refusal and the PUT-time underpayment message.
- No protocol cutover. Nodes and clients roll independently.
- The wire discriminants of every pre-existing message and error are pinned by a regression test, so the append-only property this rests on is enforced rather than assumed.

### Negative / Trade-offs

- **It does not fix the current burn.** A client too old to settle correctly is also too old to declare a version, so the gate cannot see the population causing today's rejections. Only the reworded error reaches them. Driving client adoption remains the cheaper and faster remedy for the incident that prompted this.
- **Merkle storers are not exactly the quoted peers.** The gate covers the 16 candidates a client quotes, but the chunk is stored by each chunk's close group, which may include a peer that never quoted. A storer outside the candidate set can still refuse at PUT time. This narrows the exposure substantially without closing it, and only option 3 closes it fully.
- The fallback costs one extra timeout per silent peer during rollout. Requests run concurrently, so the worst case is 2x the quote timeout overall.
- Clients declaring a version are refused by nodes that have not upgraded. Harmless today because no node has a lower `CURRENT`, but it makes node rollout a prerequisite for the next settlement bump.

### Neutral / Operational

- Deploy order is **nodes before clients**, since a node on `ant-protocol` 2.3.x cannot decode versioned requests. The fallback makes this a preference rather than a hard gate.
- The unversioned-quote counter is the input to the follow-up decision above.
- `ant-protocol` moves 2.3.2 -> 2.4.0. Additive, minor.

## Validation

- **Wire safety.** `appending_v2_variants_leaves_existing_discriminants_untouched` and `client_update_required_is_appended_to_protocol_error` pin the discriminant of every pre-existing variant. If either fails, older peers are misreading current traffic.
- **Range policy.** `a_newer_settlement_version_is_refused_rather_than_assumed_compatible` pins the upper bound, which is the specific error this ADR corrects.
- **Refusal direction.** `a_newer_settlement_version_is_refused_as_this_nodes_fault` and `the_two_refusals_do_not_blame_the_same_party` pin that a lagging node never reports a client fault.
- **Terminality.** `a_refusal_aborts_quote_collection_instead_of_counting_as_one_bad_peer` pins that a refusal stops collection rather than joining the failure list, which is what would otherwise let the remaining peers form a quorum and pay anyway.
- **Downgrade bound.** The compile-time assertion in the client, plus `only_silence_triggers_the_legacy_retry`.
- **Still outstanding at the time of writing:** a mixed-version dev testnet exercising legacy node, upgraded node, structured refusal, lost refusal, and send failure against real peers. The unit tests pin the decisions; they do not prove the behaviour end to end.

### Re-open triggers

- The unversioned-quote count failing to decay, which would mean a long tail of clients the gate can never protect and would raise the priority of option 3.
- Any settlement change that is **not** a monotonic increase, which makes the upper bound load-bearing for the first time.
- Evidence of peers selectively dropping versioned requests, which would mean the downgrade path is being probed and the fallback should be retired early.
- A decision to move the multiplier on-chain, which would supersede most of this.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
