# ADR-0016: Pointers — paid mutable references with an immutable owner

- **Status:** Proposed
- **Date:** 2026-09-18
- **Decision owners:** Anselme (@grumbach)
- **Related:** ADR-0002 (audit), ADR-0004 (commitment-bound pricing), ADR-0008 (per-record pricing), ADR-0009 (audit families), ADR-0011 (capacity-gated discovery), ADR-0014 (file store), ADR-0015 (browser clients)

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

### Storage commitments and audits

A node commits to the pointers it is responsible for in the same signed storage
commitment as its chunks (ADR-0002, ADR-0004), so they are priced and audited as
chunks are.

- **Leaf.** A chunk is committed as `(key, key)`, since its address is the hash
  of its bytes. A pointer's address is not, and its bytes change with every
  update, so it is committed as `(A, pointer_leaf_hash(A))`, a BLAKE3 derive-key
  of the address under its own context. The root binds which pointers a node
  holds, never their current state, so an update does not move it and no audit
  can fail an honest holder for having taken one mid-audit.
- **Price.** A quote is priced from the key count of the commitment it pins, so
  every committed pointer counts toward it exactly as a chunk does.
- **Round 1.** A pointer leaf is reported at its address with that hash, the
  fixed record length, and a nonced root over the bytes of the record the node
  holds, under the audit's fresh nonce, as a chunk leaf's is. So the node has to
  read every pointer in the audited subtree before it learns which few will be
  sampled. The auditor accepts that one leaf shape besides `(key, key)`, and only
  at exactly a pointer's length, so it cannot stand in for a chunk of any other
  size. A node that has lost a committed pointer refuses round 1, which is a
  confirmed failure, as a lost chunk is.
- **Round 2.** Where a chunk is proved by a Bao slice and a nonced opening, a
  pointer is proved by its whole signed record. The auditor checks the
  signature, that the record belongs at the committed address, and that its
  nonced root is the one round 1 gave. A peer signs its own commitment, so
  without the signature check it could commit any key under the hash of cheap
  bytes it holds; without the nonced root it could hold nothing and fetch the
  sampled records on demand. At most five records are opened, a few tens of
  kilobytes, well under the audit message ceiling.
- **Updates between the rounds.** The owner may update a pointer after round 1
  bound it. The store keeps the record an update replaced for five minutes,
  longer than an audit session lives, and round 2 serves it beside the new one;
  the auditor accepts whichever matches. Two updates to one pointer inside the
  same audit would fail an honest holder, and would take the owner two paid
  updates within seconds of each other.
- **Retention and pruning.** A retained commitment that still holds a pointer
  vetoes its deletion, as for a chunk, so a peer pinning that commitment can
  still audit it. The persisted retention keeps which leaves are pointers in a
  file beside it, keyed by commitment hash, so a restart rebuilds the exact
  signed root. The retention file itself is unchanged, so a node rolled back to
  an earlier release still reloads every commitment it can answer for, and
  drops only those that commit a pointer.

Round 2 carries a new slice item, so the subtree audit's protocol id moves to
`v2`, as ADR-0009 did before. Nodes on different ids do not audit each other
across the upgrade. A round-1 request that goes unanswered costs the auditor the
bounded trust penalty ADR-0009 accepted; nothing is misjudged as missing data.

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
| Commit to pointers it does not hold, for price or audit credit | A committed pointer is proved in round 2 by the whole signed record, which the auditor verifies and checks belongs at the address; the pointer leaf shape is accepted only at the fixed record length |
| Relay pointers instead of storing them | Round 1 binds a nonced root over the bytes of every pointer in the audited subtree before the sample is drawn, and round 2 must reproduce one. Another replica's copy of the same state does not match: every signature is randomised. Still weaker than for a chunk by nature: a record is 5 KB, so fetching a whole subtree of them on demand costs a relay far less than a subtree of chunks would |
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
- A pointer audit opens a whole 5,303-byte record, and up to two of them after
  an update, where a chunk audit opens one 1 KiB block, so a round 2 over
  pointers is several times larger. It stays bounded by the five-leaf cap.
- A node keeps the record each update replaced in memory for five minutes, up
  to 2,048 of them, about 11 MB.
- The subtree audit's protocol id moved to `v2`, so across the upgrade the
  old and new releases do not audit each other.

## Implementation status

Built: the record and wire messages (`ant-protocol`); the store with
merge-on-put; request dispatch; payment routed at `state_id` with the close
group of `A`; admission gates; cross-kind refusal; per-request latency events
beside the chunk ones (`pointer_put_rpc`, `pointer_get_rpc`); and the client —
create, update, quorum store, merged reads and chain resolution, a write that
falls short retried with the proof it already paid for, a split payment for an
external signer, and the `ant pointer` commands.

**Built: replication** (see Replication above): fresh offers with payment,
neighbour-sync repair by quorum over exact states, pruning with possession
proofs, and post-offer possession checks, wired into the engine's sync rounds,
churn triggers and cycle completion. A node that missed an update, joined late,
or lost a record is brought level by the next sync round rather than the next
write.

**Built: commitments and audits** (see Storage commitments and audits above):
responsible pointers are leaves of the storage commitment, count toward the
quoted price, are spot-checked by the subtree audit in both rounds, survive a
restart in the persisted retention, and are kept from pruning while a retained
commitment holds them.

**Built: browser clients** (ADR-0015). Each of the four decisions at that
security boundary is made explicitly:

- **Admission.** The WebRTC-direct listener admits a pointer GET and a paid
  pointer PUT through `chunk_protocol`, each bounded by the small response size
  a quote gets. One record is 5,303 bytes, well inside it.
- **Sanitizing.** Replies pass the sanitizer. A pointer outcome names only an
  address and a state identifier, and a record is owner-signed public data. An
  error is redacted as for a chunk, and a refused payment is reported without
  its detail.
- **Classification.** A pointer PUT is a paid write: it takes the data lane,
  holds its connection exclusively as a chunk PUT does, and goes only to nodes
  on the page's payment network. A pointer GET returns one small record, so it
  stays on the RPC lane, like a quote, and needs no bulk read slot.
- **Rules.** The browser runs the native client's own read quorum,
  corroboration, write quorum and chain resolution. Only the wallet is the
  page's.

A node advertises `pointer_protocol` in HELLO when it admits pointers and has a
pointer store to serve them from. A browser
client never sends a pointer request to a node that does not, so an older node's
refusal is never mistaken for a failed peer. The owner key crosses into the page
as its 32-byte FIPS 204 seed. A pointer payment is one quote and, unlike a file
upload, keeps no recovery journal: a payment interrupted between broadcast and
receipt is paid again on retry.

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
- From a browser: a node admits pointer requests at its WebRTC boundary, bounds
  a full record inside the small response limit, and passes every pointer reply
  through the sanitizer with errors redacted. In real Chromium against a live
  local network with on-chain payment, a pointer is created, updated, pointed
  at a second pointer, read back by a client that wrote nothing and resolved
  down the chain to its chunk.
- Storage audits, through the live responders and judged by the auditor's own
  checks: a node holding committed pointers and chunks passes both rounds; an
  update between the rounds does not fail it, and does if the replaced record
  is not kept; a node that lost a committed pointer fails round 1, and one that
  loses it after round 1 is caught in round 2; another owner's valid record is
  not proof of the committed one; a relay that answers round 1 without the
  bytes fails, as does one serving another replica's copy of the same state; a
  pointer leaf at any other length is refused. Over a live network, a node holding its
  committed pointers passes the audit and one that dropped them fails it.
- A commitment holding pointers survives a restart with its exact pin. An
  older release reading the same retention keeps the chunk-only commitment a
  peer pinned before the upgrade, and a pointer-leaves file from another
  snapshot attaches nothing.
- Pruning keeps a pointer a retained commitment holds, and drops it once none
  does.
- Fresh offers, hints, fetches and state queries are covered by the replication
  protocol's per-variant tests: family, size ceiling, round-trip.
- End to end against a live testnet with real settlement: create, update, read
  back, resolve a chain to its chunk, repeat a stored state, read an address
  nobody wrote. Every close-group node answers a paid update to a pointer it
  already holds with success, not a refusal. A record that skips counters is
  taken. Nodes that missed updates take the next one and the group converges.
  A fork at one counter across the group reads as its merge winner, and one
  update at the next counter heals it on every node.
