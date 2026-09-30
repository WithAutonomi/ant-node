# ADR-0018: Pointer ownership transfer by final redirection

- **Status:** Proposed
- **Date:** 2026-09-29
- **Decision owners:** Anselme (@grumbach)
- **Reviewers:** TBD
- **Supersedes:** none. Amends ADR-0016's merge rule at the final counter.
- **Superseded by:** none
- **Related:** ADR-0016 (pointers), ADR-0005 (repair quorum); V2-1354; WithAutonomi/ant-protocol#40, WithAutonomi/ant-node#239, WithAutonomi/ant-client#210

## Context

ADR-0016 fixes a pointer's owner key at creation and offers handover only as
indirection: the owner points the pointer at a pointer the recipient owns. The
former owner keeps its key, so that is a revocable forwarding and not a sale.
The one thing that could make it stick is the counter running out, and under
ADR-0016 it does not:

```text
1. larger counter
2. smaller target bytes
```

At `counter == u64::MAX` no counter is larger, but rule 2 still applies. A
former owner who handed the address over at `u64::MAX` can sign another state
at `u64::MAX` whose target sorts first — about two tries of grinding — and it
displaces the handover on every node, deterministically. ADR-0016 says so
("does not even freeze the pointer") and tells owners to migrate *before* the
final counter, which is exactly the revocable forwarding again.

People want to hand pointers over — a name, an application's root, a published
handle — while every reader keeps using the same address. The address derives
from the owner key, so it cannot follow a new key. What the address *resolves
to* can.

## Decision Drivers

- The address readers use must not change.
- No new record type, field, message or storage format; nothing a node has to
  interpret beyond the counter it already compares.
- Once a node holds a transfer, no arrival may move it off, the former
  owner's included.
- Forks the owner can still make must be detectable by any reader, and must
  not be able to take a transfer back from the nodes that hold it.
- Below the final counter nothing changes: ADR-0016's convergence argument
  still holds there.

## Considered Options

1. **ADR-0016 as is.** Handover by revocable forwarding. Not a transfer.
2. **Certificates and epochs** (ADR-0016's withdrawn alternative): a transfer
   certificate chain, an admission index per epoch and a 5-of-7 branch quorum.
   Real re-keying, at the cost of a second record type, lineage walks, Sybil
   exposure in ownership and a stuck-not-reversed failure mode under churn.
3. **Final state resolved by target, as today.** Grindable in about two tries.
4. **Final state resolved by payment time or order.** A pre-buy defeats it:
   pay early, withhold, publish later. Clock trust besides.
5. **A final state is replaced by nothing; the first one a node takes is the
   one it keeps.** Clients settle the owner's only remaining fork by the close
   group's majority, and nodes look before taking one.

## Decision

We choose option 5.

### Merge

One rule ahead of ADR-0016's two:

```text
0. a final state (counter == u64::MAX) is replaced by nothing
1. larger counter
2. smaller target bytes
```

Below the final counter the order is ADR-0016's, total and deterministic. At
it, two *different* final states are unordered, so each node keeps whichever it
took first. `replaces` stays a strict partial order — never both ways round,
transitive — and every pair of distinct states is ordered except two final
ones.

This lives in `ant_protocol::pointer::PointerState::replaces`, so the node's
store, its admission gate, fresh offers, repair and hints all take it without a
line of their own.

### What this changes in ADR-0016

ADR-0016 is left as written. Where the two disagree, this ADR holds, at the
final counter only:

- ADR-0016's merge rule gains rule 0 above.
- "An owner who jumps straight to `u64::MAX` ... does not even freeze the
  pointer" no longer holds: a state at `u64::MAX` is the last one the pointer
  holds on every node that takes it.
- "Ownership cannot change ... a revocable forwarding state, not a sale" no
  longer holds for a forwarding signed at the final counter: no node that holds
  it gives it up. The owner key still cannot change, and a forwarding below the
  final counter is still revocable.

### Transfer

A transfer is the final state whose target is another pointer:

```text
counter = u64::MAX
target  = (Pointer, recipient)      recipient = the new owner's pointer address
```

`Pointer::transfer_to` signs it; `transferred_to()` recognises it. A final state
with any other target freezes the pointer — nobody receives it. A pointer target
below the final counter is still ADR-0016's revocable forwarding.

Readers already follow pointer targets (`pointer_resolve`), so a transferred
address resolves through the recipient's pointer, which only the recipient can
move. The recipient's pointer should serve that one address: a pointer's
address derives from its owner key, so everything handed to the same recipient
pointer resolves to the same place. A recipient uses a fresh key per received
pointer.

### The fork that remains

Only the owner can sign a final state, so only the owner can fork one. It
keeps the earlier record and its key, so it can sign a second final state at
once or much later, and any node the first has not reached will take it. Each
node keeps its first. Nothing local can settle that, and this design does not
try. What it guarantees instead:

- **No fork after the fact.** Once a node holds a final state, no arrival —
  client PUT, fresh offer or repair — moves it off it. A second final state can
  only land on a node that holds none.
- **Nodes look before a final state.** Before taking a final state it does not
  hold, from a client or from a fresh offer, a node asks its close group which
  state each holds. A peer claiming a *different* final state is asked for the
  record, and if it verifies — only the owner could have signed it — the node
  refuses, answering `Stale` with the state the group proved. A claim alone
  refuses nothing, so one dishonest peer cannot block a transfer. Each peer's
  question and fetch run as one pipeline, all at once, so a peer that claims a
  rival and then stalls its fetch cannot hide another peer's proof until the
  budget runs out. The look runs after payment is verified, asks only peers
  that have sent a pointer message, and is bounded at four seconds; silence
  proves nothing and the write goes ahead. This is what closes the gap the
  merge rule leaves: a node that joined the group after the transfer would
  otherwise take a second final state on the merge rule alone.
- **A look costs one round, once.** A payment proof, once verified, is cached,
  so replaying one paid final state costs its sender nothing after the first
  time. A node therefore remembers each final state a look proved, up to two
  per address and 16,384 addresses, oldest forgotten first, and never lets a
  later proof replace an earlier one; it refuses a replayed loser from that
  memory, ahead of the signature check and without asking anyone. A look that
  found nothing answers the same state again for ten seconds without asking.
  Looks for one address wait their turn, so replays queued behind a look find
  its answer, and a burst costs one round; at most 64 run at once, and one
  that cannot start within two seconds answers the PUT with an error and
  drops the fresh offer, neither taking nor refusing the state for good, so
  the write can be tried again.
  Two seconds of waiting and four of looking stay inside the client's
  ten-second store timeout. Flooding past that needs a new paid final state
  per round.
- **A node restores its own final state without looking.** A node that lost
  the file of a final state it held is admitted that exact state again and
  nothing else (ADR-0016's lost-record rule), so taking it back is a restore,
  not a new final state. It asks nobody: a peer on the other side of a fork
  would otherwise keep it from restoring its own copy for good.
- **Readers see the majority, and see forks.** A client read that meets a final
  state is settled only once one final state is held by a majority of the close
  group, and returns that one. If two different final states are seen and
  neither has a majority, the read fails as forked rather than guess. One final
  state below a majority with no rival is returned once corroborated, as any
  state is: it is a transfer still spreading.
- **Recipients check before they rely on it.** `pointer_finality` asks the
  whole group and answers `Open`, `Settling` (one final state, short of a
  majority), `Final` (one final state, a majority holds it, no rival seen) or
  `Forked` (rivals seen; the majority's state if there is one). A recipient
  treats the transfer as done only on `Final`; anything else is the former
  owner's to explain.

### Replication

- **Repair** is the merge rule over quorum-backed states, so a node holding a
  final state adopts nothing else, and a node holding none adopts the final
  state a quorum holds. Between two final states a group wide enough to back
  both at quorum — never a seven-node group at four — the larger side is
  adopted, not whichever answered first.
- **Hints** for a different final state are dropped by a node holding one,
  since the hint cannot replace it. No refetch loop.
- **Possession.** A member holding a *different final* state is not penalised
  when checked for the one this node offered: it holds what the merge rule told
  it to, and the fork is the owner's. It is logged at warn. A member holding
  nothing is penalised as before.

### Client

- `pointer_transfer` refuses before paying if the pointer is already final, if
  the recipient is the pointer itself, if the recipient pointer does not exist,
  or if the recipient's chain leads back to this address. It then signs,
  pays, stores and reports `pointer_finality`.
- `pointer_update` on a final pointer refuses before paying, as it always did
  when the counter could not advance.
- `pointer_controller` follows transfers — final pointer-targeted states only —
  to the pointer whose owner now decides what the address resolves to.

## Consequences

### Positive

- Pointers can be handed over for good, and the address readers use never
  changes.
- No new record, field, message or storage format. The wire is untouched; the
  only protocol change is one comparison.
- Once the handover lands on a node, the former owner has no move there: no
  larger counter exists and no equal one replaces.
- A handover can be chained: the recipient can transfer its own pointer on.
- ADR-0016's "revocable forwarding" and "migrate before the final counter"
  caveats are gone: migration *is* the final update.

### Negative / Trade-offs

- **A race is a permanent fork.** An owner who signs two final states and races
  them leaves each node on its first, forever. With a majority on one side,
  reads return that side and flag the fork to anyone who checks finality. With
  no majority, reads of that pointer fail as forked, and nothing — not the
  owner, not repair — can fix it. Only the owner can do this, and only to its
  own pointer, as only the owner can lose its key.
- **A transfer is irreversible.** One sent to the wrong recipient pointer is
  gone. The client checks the recipient exists and does not loop back; it
  cannot check intent.
- **The look before a final state is not a lock.** It is fail-open on silence
  and bounded in time, and it only runs when a node has learned which peers
  understand pointers, which takes a sync round after joining. A node asked in
  that first round, or one whose group cannot answer in four seconds, takes a
  second final state on the merge rule alone. Reads still return the majority
  side; the residual risk is a minority fork that `pointer_finality` reports.
- Under a flood of distinct paid final states a node answers some honest final
  PUTs with an error rather than look for them late. A client retries one such
  refusal as a shortfall; several make the write fail, and the owner tries
  again.
- A final PUT costs its node one state query per capable close-group peer, and
  a fetch per claimed rival, before it commits.
- **Mixed fleets.** A node on ADR-0016's rule still lets a smaller-target final
  state displace the first. Until a close group's majority runs this rule a
  former owner can win back the nodes that do not. Reads follow the majority, so
  the handover holds wherever most of the group has upgraded; recipients should
  wait for the upgrade before relying on a transfer. Nothing on the wire tells
  the two rules apart: the pointer format version is unchanged, so no node can
  refuse to replicate with a peer on the old rule.
- Transferred reads take one extra hop, and a chain of transfers one per hop,
  bounded by the client's resolve depth.

### Neutral / Operational

- A node refusing a final state because its group proved another logs it at
  info with both state ids; a possession check that finds the other side of a
  fork logs at warn. Either is the owner equivocating.
- Pricing, payments, audits and storage commitments are unchanged: a final
  state is a state, paid, stored, committed and audited like any other.

## Validation

- Protocol: a final state is replaced by no counter and no other final state,
  whatever its target; below the final counter the order is unchanged;
  `replaces` is a strict partial order over a set including final states, total
  except between two of them; a fold keeps the first final state it meets;
  `transfer_to` signs at the final counter to the recipient, refuses to sign past
  a final record, and only a final pointer target counts as a transfer.
- Node, store: a stored transfer is not displaced by a final state whose target
  sorts first, nor by any lower counter.
- Node, properties: with one final state among the records every delivery order
  converges on it, exhaustively over all permutations; with two, the first
  delivered is kept.
- Node, request handler: a final state the group proves already superseded is
  refused and named, and nothing is written; one nobody contradicts is taken;
  the group is asked only about a final state the node lacks; two final states
  raced to two nodes leave each on its first; a node restores its own lost
  final state without asking, and still refuses the rival; a busy look neither
  takes nor refuses a final state for good; a proven loser is refused again
  before its signature is checked, and without asking.
- Node, the look: a peer that claims a rival and stalls its fetch does not hide
  another peer's proof; a claim the served record does not back is no proof;
  proven final states refuse others, not themselves, and the oldest is
  forgotten first past the cap; a second proof at an address never replaces
  the first; replays queued behind a look reuse its answer, and a proof
  answers every replay of the loser.
- Node, repair: a node holding a final state adopts nothing else; of two final
  states with quorum, the larger side is adopted in either answer order.
- Node, live network: a transfer written to one node reaches the group and no
  node takes a second final state; a node that missed the transfer refuses a
  different one because a peer serves the one it holds, and still takes the
  group's own; the possession check does not penalise the other side of a fork
  and still penalises a member holding nothing.
- Client: reads over a group holding a transfer, a majority fork, a no-majority
  fork and a transfer still spreading; the finality check for each; transfer
  preflight refusals; end to end against a local testnet with real settlement,
  a transfer is final, readers are redirected to the recipient's pointer, the
  recipient moves it, and the former owner's attempt to take it back is refused
  by every node.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human
review**. Accepted ADRs are immutable: create a new superseding ADR rather than
editing an Accepted ADR.
