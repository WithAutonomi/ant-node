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
signed. The address and `state_id` are hashes of fields already present, so they
are computed rather than stored.

The key is carried because it has to be: ML-DSA has no key recovery and a
1,952-byte key cannot be a 32-byte address. That is the whole reason a pointer
is 5,303 bytes rather than ~3,350, and the price of validating one with no
fetch.

### Two identities

```text
A        = BLAKE3("autonomi.pointer.address.v1" || owner)   routes
state_id = BLAKE3("autonomi.pointer.state.v1"   || body)    authorizes payment
```

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
forged record for someone else's address buys no cryptography. The commit
re-checks under its lock, because a newer state can land while payment verifies.

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
| Pay for a chunk to fund a pointer | Paid cache keyed by a typed `Chunk` vs `Pointer` target, never a raw 32-byte value a crafted chunk could occupy. The quote signs only its content, not the record kind, so this is a cache defence rather than a cryptographic one |
| Merkle proof with no issuer check | Refused for pointers; single-node proofs only |
| Downgrade the format | `version` is signed and inside `state_id`; unknown versions are refused |
| Unknown target kind | Carried, never interpreted — a node stores 33 opaque bytes |
| Collide a pointer and a chunk address | Refused in both directions. The two stores take separate locks, so simultaneous commits of both kinds at one address are not yet atomic |
| Peer lies about storing a pointer | Every acknowledgement must name the address and state the client sent, and a write needs a majority of the close group — the same group, by the same call, that a read asks, so an acknowledged pointer is readable |
| Node claims a record it no longer holds | An index entry is only a claim about a file; before answering "unchanged" or "stale" the node reads the file back, and a lost or corrupt one makes the submission a repair |

## Consequences

- Validating a pointer needs nothing but the pointer — no quorum, no lineage, no
  Sybil exposure in ownership.
- Creation is one record and one payment, with no retention dependency.
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
- A majority of the group answering ends a write or a read, so one unreachable
  peer cannot stall either; a minority is reported as a shortfall, never
  presented as the network's answer.
- A resubmission repairs a record whose file the disk lost, rather than being
  acknowledged as unchanged.
