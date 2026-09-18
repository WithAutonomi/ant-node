# ADR-0015: Pointers — paid mutable references with an immutable owner

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
    counter: u64,             //     8 — 0 to create, +1 per paid update
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

Creation is `counter = 0`. Each update is `counter + 1`. Both are paid against
their own `state_id`, so **one payment buys exactly one increment**.

The client path enforces `+1`. Replication accepts any strictly greater counter,
because a replica that missed an update must be able to catch up; refusing the
gap would leave it permanently stale instead.

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

## What this defends against

| Attack | Defence |
|---|---|
| Tamper with any byte | Signature over the whole body |
| Swap the owner key | `A` is derived from it; the record no longer belongs at its address |
| Store at someone else's address | Same |
| Fork / equivocate at one counter | Total order on `(counter, target)`: every node given the same records picks the same one, and a read merges the close group's answers rather than trusting the first. Convergence *across* the network still needs replication — see Not built |
| Replay an older record | Loses on counter |
| Re-sign one paid state N times | Equal state never replaces; nothing is written |
| Pay once, jump the counter | Client updates must be `+1` |
| Pay for a chunk to fund a pointer | A quote signs its content, not the record kind, so the defence is that the content cannot be shared: putting a chunk on a `state_id` means breaking BLAKE3 across its two modes. The paid cache is keyed by a typed `Chunk` vs `Pointer` target as well, so the two never alias even in memory, whatever the bytes |
| Merkle proof with no issuer check | Refused for pointers; single-node proofs only |
| Downgrade the format | `version` is signed and inside `state_id`; unknown versions are refused |
| Unknown target kind | Carried, never interpreted — a node stores 33 opaque bytes |
| Collide a pointer and a chunk address | Takes a cross-mode BLAKE3 break, and is refused in both directions anyway. The two stores take separate locks, so simultaneous commits of both kinds at one address are not yet atomic |
| Peer lies about storing a pointer | Every acknowledgement must name the address and state the client sent. A read asks the same group by the same definition, so the quorums intersect — though each does its own lookup, so churn between them is not covered |
| One peer decides what a pointer says | A read returns a state only if two of the answering peers name it, and a write must reach a majority **plus one** so that two always do. Otherwise a single close-group peer serving an owner-signed state nobody paid to store would be believed by every reader: the record verifies, belongs at the address, and wins the merge. It cannot make a second peer agree. The read counts each state separately, so a state one peer names cannot bury the one the rest agree on — that would be denial of service in place of forgery, and it is also what an ordinary read during an update looks like |
| Two peers decide it | **Not defended against.** Two colluding close-group peers clear the bar, and only the owner can sign, so what this buys is the owner's own updates unpaid. Raising the bar only raises the number of nodes to grind: both the pointer's address and a node's id are choosable, so an owner determined to sit beside their own pointer can reach any fixed threshold. What actually answers it is replication and audits, neither of which is built |
| Node claims a record it no longer holds | An index entry is only a claim about a file. Before answering "unchanged" or "stale" the node reads the record back and checks it is still the one the index names; if it is not, the node stops answering for that address and the arrival becomes a repair. It keeps what it lost, because an address nothing is known about admits only a counter 0 record, and a loss above that would otherwise be permanent |

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
- The inlined key costs 1,920 bytes on every read, forever — a deliberate trade
  for self-contained validation.
- Determinism is not freshness: an eclipsed reader can be handed an older,
  correctly signed value and cannot tell.
- Replicas may hold different valid signatures of one state; nothing compares
  record bytes across replicas.
- Pointers do not take part in storage commitments or audits. The audit format
  is untouched, so no protocol family is bumped and no rollout pauses. Auditing
  them needs round 2 to serve a whole record — a peer signs its own commitment,
  so without that it could name any key with the hash of cheap bytes it holds —
  and that lands with replication.

## Implementation status

Built: the record and wire messages (`ant-protocol`); the store with
merge-on-put; request dispatch; payment routed at `state_id` with the close
group of `A`; admission gates; cross-kind refusal; and the client — create,
update, quorum store, merged reads and chain resolution.

**Not built: replication.** No node forwards a pointer to another, so the copies
that exist are the ones the client wrote. That is the load-bearing gap: the
merge rule guarantees nodes holding the same records agree, and nothing yet
guarantees they hold the same records. Until it lands, availability and
cross-network fork convergence are the client's doing, not the network's.

Two consequences follow from it and land with it. A node that joins a close
group after a pointer was created can never obtain it: the increment rule admits
only a counter 0 record at an address nothing is known about. And a node that
loses a record can repair it while it is running — it keeps what it lost, and
takes back that state or any that replaces it — but not across a restart, where
a missing file leaves nothing to remember. Both are the same missing mechanism:
a node cannot ask another node for a record.

Also not built: pointer participation in commitments and audits, which depends
on the same work.

## Validation

- Every delivery order of a record set converges to one value, exhaustively over
  all permutations, including on a node started empty and one restarted.
- 64 valid signatures over one paid state yield one stored record and one file.
- A resubmission and a stale arrival are both refused before any signature check.
- Creation is counter 0; an update is `+1`; every jump — including to `u64::MAX`
  and a wrap back to 0 — is refused as a non-successor.
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
- The chunk preimages the old prefix construction handed out no longer land on
  either identity. (No test can say more: that no content does is the preimage
  assumption, not a property one can check.)
- End to end against a live testnet with real settlement: create, update, read
  back, resolve a chain to its chunk, repeat a stored state, read an address
  nobody wrote, and refuse a signed record that skips the counter.
