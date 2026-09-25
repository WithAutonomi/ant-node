# ADR-0016: Pointers — paid mutable references with an immutable owner

- **Status:** Proposed
- **Date:** 2026-09-18
- **Decision owners:** Anselme (@grumbach)
- **Related:** ADR-0002 (audit), ADR-0008 (per-record pricing), ADR-0009 (audit families), ADR-0014 (file store)

## Context

2.0 stores only immutable chunks. 1.0's pointer had three defects: updates
after the first were free, the merge rule diverged permanently on equal
counters, and the address *was* the owner's key, so ownership could never
change.

We fix the first two and keep the third deliberately. A former owner keeps its
key forever, so transferable ownership cannot be made fork-proof by any local
rule: hash tie-breaks are grindable in ~2 keygens and payment-order ties fall to
a pre-buy. Declining transfer is what lets this design be small enough to trust.

## Decision

One record. No genesis object, no certificates, no lineage.

```rust
pub struct Pointer {          // 5,303 bytes
    version: u8,              //     1
    owner: MlDsa65PublicKey,  // 1,952 — the identity; the address derives from it
    counter: u64,             //     8 — orders states; larger wins
    target: PointerTarget,    //    33 — kind tag + address; opaque to a node
    sig: MlDsa65Signature,    // 3,309 — over every field above
}
```

Five fields and nothing else — no cached bytes, no cached identifiers. Encoding
is fixed-width, big-endian and hand-rolled with no serde, so there is exactly
one byte sequence for a record and re-encoding is always identical to what was
signed. The address and `state_id` are derived from fields
already present, so they are computed rather than stored.

The key is carried because it has to be: ML-DSA has no key recovery and a
1,952-byte key cannot be a 32-byte address. That is the whole reason a pointer
is 5,303 bytes rather than ~3,350, and the price of validating one with no
fetch.

### Two identities

```text
A        = BLAKE3::derive_key("autonomi.pointer.address.v1", owner)  routes
state_id = BLAKE3::derive_key("autonomi.pointer.state.v1",   body)   authorizes payment
```

Derive-key, not a hash of a prefix. A chunk's address is `BLAKE3(content)`, so a
prefix separates nothing: a chunk holding the prefix and an owner key would land
on exactly that owner's address, letting anyone squat an address before its
owner used it, and — since `state_id` is what a pointer's storage is paid
against — letting one settled quote buy both a pointer and a chunk. Derive-key
is a different BLAKE3 mode. Both still produce 32 bytes and the ranges are not
disjoint; what changed is the cost. Landing a chunk on a pointer identity now
means finding a preimage under one mode for an output of the other, which is
the security assumption BLAKE3 is built on, rather than a string anyone can
write down.

**Public-key addressed and self-verifying.** `A` is a pure function of the owner
key, and the key is in the record, so a node validates a pointer from its own
bytes: one hash, one signature check, no fetch.

`A` and `state_id` are separate because `A` is stable for the pointer's life
while the paid identifier must change with every update — paying against `A`
would make every update after the first free.

### Pay to create, pay to update

Every stored state is paid against its own `state_id`, so **one payment buys
one state**. Creating and updating are the same operation: a node takes any
paid record that beats what it holds under the merge rule, whatever its counter.
The client creates at 0 and updates by signing one past the counter the network
serves, but nothing requires exactly one.

The counter orders states; it does not meter them. A number that is skipped is
never stored, so skipping avoids no payment that was owed. And requiring `+1`
would break catching up, since nothing replicates a pointer. A write ends once
its quorum has answered — five of the seven peers — so a peer can miss an
update, and one that joins the group later holds nothing at all. Under a `+1`
rule either would refuse every later update for good, and three such peers
would leave no write able to reach its quorum. Under the merge rule each takes
the next update, however far ahead of it that is.

An owner who jumps straight to `u64::MAX` limits only themself, and does not
even freeze the pointer: equal counters still resolve by target, below.

### Merge

```text
1. larger counter
2. smaller target bytes
```

A total order on the states of **one address**. Records of different owners are
not comparable and never contend. **Equal state never replaces**: ML-DSA signing
is randomized, so one state has unboundedly many valid encodings, and ordering
record *bytes* would let an owner sign one paid state repeatedly and have every
submission win.

### Validation order

```text
length → version → structure → compare with held → admission → signature → payment → commit
```

Cheap first. A resubmission of what is held is refused before any signature
check. Admission (capacity, responsibility for `A`) precedes the signature, so a
forged record for someone else's address buys no cryptography. "Compare with
held" reads the held record back rather than trusting the index, so no answer
describes a record the node cannot serve. The commit re-checks under its lock,
because a newer state can land while payment verifies. Every step off the async
executor: the read, the signature check and the write each run on a blocking
thread, so a flood of arrivals cannot occupy the runtime's workers.

### Replication

Pointers replicate through the same engine chunks do — the same close groups,
neighbour-sync rounds, churn triggers, quorum, pruning and possession rules —
but by **state**, not by key. The chunk pipeline assumes a record never changes
and that its key is the hash of its bytes; a pointer's address is stable while
its state changes, and two honest replicas may hold different valid signatures
over one state.

- **Fresh.** A node that accepts a paid state from a client forwards the record,
  with the proof that paid for it, to the rest of the close group. Each receiver
  checks the signature, its own responsibility (across the paid width, as for a
  chunk offer) and the payment itself before storing. So a paid state that
  reached one honest node reaches the whole group, whichever members the client
  wrote to.
- **Repair.** Every neighbour-sync round pushes hints — the states the sender
  holds that the receiver should hold — to the peers being synced, and a peer
  that syncs with a node gets that node's hints back. A receiver that lacks a
  hinted state, or holds an older one, asks the close group which state each
  holds, adopts the best state a quorum of them hold **exactly**, and fetches it
  from one of them. The record verifies itself; the quorum stands in for the
  payment proof, as presence quorum does for a chunk. The quorum is the one a
  chunk needs, counted over the whole close group: a peer that cannot be asked
  counts as unanswered, never as a vote. This is how a node that missed an
  update, joined late, or lost a record across a restart is brought level.
- **Pruning.** A record the node has been outside the retention width of for the
  hysteresis period is deleted — at once if the node is outside a complete
  paid-width group, otherwise only once all but one of the current close group
  prove they hold that state or a newer one by returning a valid record. A proof
  is a record, not a claim: signatures are checked.
- **Possession.** Some minutes after offering a fresh state, the offering node
  asks each member for the record. One that is still responsible and cannot
  produce that state or a newer one is penalised, as a chunk holder is.

Six messages carry this, appended to the replication enum so every earlier
discriminant keeps its value: a fresh offer and a hint push (one-way), and a
fetch and a state query with their responses. An older peer cannot decode them.
One-way pushes to it are simply lost, and requests only ever go to peers that
have sent a pointer message themselves — a hint push goes out every round, empty
or not, so capability is learned within a cycle — so an older peer is never asked
something it cannot answer and never penalised for its silence.

Records are kept one file each under `{root}/pointers/<shard>/`, 256 shards by
the address's last byte as the chunk store keeps them. Opening the store parses
each record's structure but does not verify its signature; every record was
verified when it was committed and every read verifies it again.

## What this defends against

| Attack | Defence |
|---|---|
| Tamper with any byte | Signature over the whole body |
| Swap the owner key | `A` is derived from it; the record no longer belongs at its address |
| Store at someone else's address | Same |
| Fork / equivocate at one counter | Total order on `(counter, target)`: every node given the same records picks the same one, a read merges the close group's answers rather than trusting the first, and replication gives every member the states that reached a quorum, so the group converges |
| Replay an older record | Loses on counter |
| Re-sign one paid state N times | Equal state never replaces; nothing is written |
| Pay once, jump the counter | Nothing to defend: one payment stores one state whatever its counter, and a skipped number is never stored |
| Pay for a chunk to fund a pointer | A quote signs its content, not the record kind, so the defence is that the content cannot be shared: putting a chunk on a `state_id` means breaking BLAKE3 across its two modes. The paid cache is keyed by a typed `Chunk` vs `Pointer` target as well, so the two never alias even in memory, whatever the bytes |
| Merkle proof with no issuer check | Refused for pointers; single-node proofs only |
| Downgrade the format | `version` is signed and inside `state_id`; unknown versions are refused |
| Unknown target kind | Carried, never interpreted — a node stores 33 opaque bytes |
| Collide a pointer and a chunk address | Takes a cross-mode BLAKE3 break, and is refused in both directions anyway. The two stores take separate locks, so simultaneous commits of both kinds at one address are not yet atomic |
| Peer lies about storing a pointer | Every acknowledgement must name the address and state the client sent. A read asks the same group by the same definition, so the quorums intersect — though each does its own lookup, so churn between them is not covered |
| One peer decides what a pointer says | A read returns a state only if two of the answering peers name it, and a write must reach a majority **plus one** so that two always do. Otherwise a single close-group peer serving an owner-signed state nobody paid to store would be believed by every reader: the record verifies, belongs at the address, and wins the merge. It cannot make a second peer agree. The read counts each state separately, so a state one peer names cannot bury the one the rest agree on — that would be denial of service in place of forgery, and it is also what an ordinary read during an update looks like |
| Two peers decide it | **Not defended against, at the read.** Two colluding close-group peers clear a read's bar, and only the owner can sign, so what this buys is the owner's own updates unpaid. Replication does not spread such a state: the rest of the group adopts only what a quorum of it holds, so the honest members keep the paid state, but a reader that happens to hear from both colluders still sees theirs. Raising the read's bar only raises the number of nodes to grind: both the pointer's address and a node's id are choosable, so an owner determined to sit beside their own pointer can reach any fixed threshold |
| Get a group to adopt a state nobody paid for | Repair adopts only a state a quorum of the close group hold exactly, counted over the whole group, and a fresh offer is stored only after the receiver verifies its payment itself |
| Node claims a record it no longer holds | An index entry is only a claim about a file. Before answering "unchanged" or "stale" the node reads the record back and checks it is still the one the index names; if it is not, the node stops answering for that address and the arrival becomes a repair. It keeps what it lost, so the lost state is taken back and nothing older is: an address nothing is known about admits any record, and a replay could otherwise roll the node back. That check parses the body, so a signature corrupted in place passes it and is caught on the next read instead — verifying there would put ML-DSA in front of the payment gate, which is the one place it must not be |

## Consequences

- Validating a pointer needs nothing but the pointer — no quorum, no lineage, no
  Sybil exposure in ownership.
- Creation is one record and one payment, with no retention dependency.
- A pointer write must reach one more peer than a chunk write does. A chunk is
  self-proving, so one copy settles it; a pointer read has to decide which of
  several signed states is current, and that answer has to come from more than
  one peer.
- **Ownership cannot change.** Handover is indirection: point at a new pointer
  the recipient owns. The old owner keeps write access forever, so it is a
  revocable forwarding state, not a sale.
- **Key compromise is permanent.** No rotation, no recovery.
- The inlined key costs 1,952 bytes on every read, forever — a deliberate trade
  for self-contained validation.
- Determinism is not freshness: an eclipsed reader can be handed an older,
  correctly signed value and cannot tell.
- Replicas may hold different valid signatures of one state; nothing compares
  record bytes across replicas.
- Pointers do not yet take part in storage commitments or audits; see
  Implementation status. Auditing them needs round 2 to serve a whole record — a
  peer signs its own commitment, so without that it could name any key with the
  hash of cheap bytes it holds.

## Implementation status

Built: the record and wire messages (`ant-protocol`); the store with
merge-on-put; request dispatch; payment routed at `state_id` with the close
group of `A`; admission gates; cross-kind refusal; and the client — create,
update, quorum store, merged reads and chain resolution.

**Built: replication** (see Replication above): fresh offers with payment,
neighbour-sync repair by quorum over exact states, pruning with possession
proofs, and post-offer possession checks, wired into the engine's sync rounds,
churn triggers and cycle completion. A node that missed an update, joined late,
or lost a record is brought level by the next sync round rather than the next
write.

**Not built yet: commitments and audits.** Pointers are not yet leaves of the
storage commitment, so they do not count toward a node's quoted price and are not
spot-checked by the subtree audit.

**Not built: browser clients.** ADR-0015's WebRTC-direct transport admits,
sanitizes and classifies message kinds by an explicit list, and pointer requests
are in none of them. The client's pointer API is therefore native-only rather
than compiled for a transport that would reject it. Reaching a pointer from a
browser needs four things, each a deliberate decision at a security boundary:
admit the two request kinds, let the response sanitizer pass their replies,
classify a pointer GET as a read and a pointer PUT as paid-exclusive, and give
the browser client the same quorum and corroboration rules the native one uses.

## Validation

- Every delivery order of a record set converges to one value, exhaustively over
  all permutations, including on a node started empty and one restarted.
- 64 valid signatures over one paid state yield one stored record and one file.
- A resubmission and a stale arrival are both refused before any signature check.
- Any paid record that beats the held one is taken, including a first record
  above counter 0 and a jump to `u64::MAX`; anything older is refused as stale,
  and the client cannot wrap a terminal counter back to 0.
- A fork at one counter held by two nodes is healed on both by any later counter.
- All 256 `version` values give distinct paid identifiers.
- Golden vectors pin the encoding, both identities and the signing context.
- A crafted chunk cannot satisfy a pointer's paid-cache entry.
- An acknowledgement naming a different address or state is refused, and a read
  keeps the winner whatever order the replies arrive in.
- A write ends as soon as its quorum acknowledges, so one unreachable peer
  cannot stall it. A read ends when a quorum has answered *and* one of the
  states they named has the backing a read demands; short of that it keeps
  asking, and if the group is exhausted without either, it reports a shortfall
  rather than presenting one peer's word as the network's answer.
- A state only one peer named does not suppress the state the others agree on,
  in any arrival order.
- The write and read thresholds overlap in at least the two peers a read
  demands, at every group width from 1 to 64.
- A resubmission repairs a record whose file the disk lost — at any counter,
  not just at creation — rather than being acknowledged as unchanged. A file
  swapped for a different valid record is not answered for either.
- Two nodes given the same two paid states in opposite orders keep the same
  record, through the request handler and its admission gate rather than the
  store alone.
- The chunk preimages the old prefix construction handed out no longer land on
  either identity. (No test can say more: that no content does is the preimage
  assumption, not a property one can check.)
- Replication across a live multi-node network: a paid PUT to one node reaches
  its whole close group; an update replaces the old state everywhere; a node that
  missed an update is repaired by neighbour sync alone; a node that joins later
  obtains existing pointers through the engine's own loops; a state only one node
  holds is not adopted, though its hints arrived; an unpaid fresh offer is
  refused; the possession check penalises only the member that dropped the
  record; pruning deletes only once the close group proves it holds the record,
  and a node far outside the group prunes without asking.
- Fresh offers, hints, fetches and state queries are covered by the replication
  protocol's per-variant tests: family, size ceiling, round-trip.
- End to end against a live testnet with real settlement: create, update, read
  back, resolve a chain to its chunk, repeat a stored state, read an address
  nobody wrote. Every close-group node answers a paid update to a pointer it
  already holds with success, not a refusal. A record that skips counters is
  taken. Nodes that missed updates take the next one and the group converges.
  A fork at one counter across the group reads as its merge winner, and one
  update at the next counter heals it on every node.
