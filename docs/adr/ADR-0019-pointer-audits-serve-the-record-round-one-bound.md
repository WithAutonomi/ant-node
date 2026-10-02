# ADR-0019: Pointer audits serve the record round 1 bound

- **Status:** Proposed
- **Date:** 2026-09-29
- **Decision owners:** Anselme (@grumbach)
- **Reviewers:** <pending>
- **Supersedes:** none. It amends one point of ADR-0016, "Updates between the
  rounds", and leaves the rest of ADR-0016 as written.
- **Superseded by:** none
- **Related:** ADR-0002 (audit), ADR-0009 (audit families), ADR-0016 (pointers)

## Context

A storage audit is two rounds (ADR-0002, ADR-0009). Round 1 reports, for every
leaf of the audited subtree, a root over the bytes the node holds, keyed by the
audit's fresh nonce. Round 2 then opens a few of those leaves, and the node must
serve bytes that reproduce the root round 1 reported.

For a pointer (ADR-0016) those bytes are the whole signed record, and the owner
may replace the record at any time with a paid update. ADR-0016 covers one
update between the rounds: the store keeps the record an update replaced for
five minutes, and round 2 serves it beside the new one. It accepts the case of
two updates:

> Two updates to one pointer inside the same audit would fail an honest holder,
> and would take the owner two paid updates within seconds of each other.

Two things make that worth closing rather than accepting.

- **The failure is charged to the wrong party.** The auditor reports
  `DigestMismatch`, a confirmed failure, and the holder takes the trust penalty
  for its owner's activity. Nothing the holder did was wrong.
- **It can be aimed.** An owner who is also a close-group auditor of the holder
  knows exactly when its round 1 has been answered, and two paid updates cost
  two writes, about 0.013 ANT each on the 990-node pointer testnet. ADR-0016
  already notes that an owner can grind a node id beside its own pointer. That
  turns an accepted edge case into a cheap way to penalise a chosen honest
  neighbour.

The cause is narrow. Round 2 serves the record held now and the one last
replaced, because the node has not kept what round 1 bound and so cannot tell
which record it owes. After two updates neither of those is the one round 1
read.

## Decision Drivers

- An honest holder must not take a confirmed failure because its owner updated
  the pointer, however often.
- No wire change and no change to what the auditor accepts. Pointers have not
  shipped in any release yet, but the smaller change is still the better one.
- Memory stays bounded against an auditor that opens many round-1 sessions, and
  running out of it must never turn into a confirmed failure either.

## Considered Options

1. **Keep ADR-0016 as written.** Cheapest, and it leaves the failure above.
2. **Serve every record held since round 1.** It needs a larger per-item cap
   than `MAX_POINTER_RECORDS_PER_ITEM`, so the auditor's check changes, and any
   cap is still one more paid update away from failing.
3. **Remember what round 1 bound, and serve that record.** Round 1 already
   reports a nonced root per pointer leaf. The node keeps those roots in the
   round-1 session it already holds, and round 2 serves the one record,
   current or replaced, whose root matches.

## Decision

We will take option 3.

- **The session keeps round 1's roots.** When a round-1 proof is about to be
  sent, the single-use session it opens keeps the nonced root reported for each
  pointer leaf, keyed by address: 64 bytes of key and root a pointer, and
  nothing for chunks. A session whose proof then fails to send keeps them until
  it expires, as it keeps its place today.
- **The store keeps every replaced record, for longer.** Every record an update
  replaces is kept in memory, not only the last one, for ten minutes rather
  than five. A round 1 can read a pointer at its start and take as long as the
  auditor waits for the largest subtree (1,024 leaves), about seven minutes
  with the default configuration, before its session even opens, and round 2
  then has the session's two minutes. A test ties the ten minutes to those two
  figures for the default configuration; an auditor configured to wait longer
  than that can outlast the record. The overall cap stays 2,048 records, about
  11 MB, oldest first wherever it is, and records past the ten minutes are
  dropped at each prune pass even when no update comes to drop them.
- **Round 2 serves the record that matches.** Among the record held now and the
  replaced records kept for that address, it serves the one whose nonced root,
  under the audit's own nonce, is the root round 1 reported. That is a single
  record, so the auditor's check and the item cap are unchanged.
- **When it cannot, it says so.** If the root matches nothing kept, because the
  record aged out or was evicted, round 2 is rejected as `Transient`, as for a
  local read error. That is the auditor's timeout lane: no trust penalty, but
  the auditor forgets the holder's standing as a proven holder of every key
  under the pinned commitment, until the holder passes again. A node that no
  longer holds the pointer reports it absent, which is a confirmed failure, as
  before, whatever replaced records it still keeps: those prove what round 1
  read, not that the pointer is still held.
- **The roots are bounded, by admission.** Every live session together keeps
  at most `MAX_SESSION_POINTER_BINDINGS` (65,536) roots, 4 MiB of payload
  before the maps' own overhead. A round 1 whose roots would not fit withholds
  its proof and answers `Transient` instead, which puts it in the auditor's
  timeout lane with no trust penalty; staying silent would read as a peer that
  did not answer. Roots are never stripped from a live session to make room:
  its round 2 is owed them. A whole session can still be evicted when the
  session count reaches `MAX_SUBTREE_SESSIONS`, as before this change, and its
  round 2 then goes to the timeout lane. Without a root for a pointer, round 2
  would reject it as `Transient` rather than guess, since the replaced records
  kept are capped and an empty history proves nothing, but a session this node
  opened always holds a root for every pointer it proved.

## Consequences

### Positive

- Updates between the rounds no longer fail an honest holder, however many.
  What remains are local limits, and none is a confirmed failure: the bound
  record evicted by more than 2,048 paid updates across the node's pointers
  inside ten minutes is reported as `Transient`, and so is a round 1 over the
  roots budget.
- Round 2 serves one pointer record where it could serve two, so it is smaller.
- The auditor, the wire format and the subtree-audit protocol id are unchanged.

### Negative / Trade-offs

- Round-1 sessions carry state they did not before, bounded by the budget
  above. Auditors that open pointer-heavy sessions faster than they complete
  can fill it, and later round 1s are then answered `Transient` until it
  drains. That costs the holder those audits' credit, not trust, much as the
  round-1 concurrency and work budgets already can.
- A responder that returns `Transient` is not proved wrong. That was already
  so, since any responder can report a local read error, so this gives a
  dishonest node no answer it did not have.
- One address can hold many replaced records inside the window, and round 2
  hashes each candidate it checks for that address. The global cap bounds that
  work to about 11 MB of keyed BLAKE3 per opened pointer, and filling it takes
  that many paid updates.
- Replaced records are kept twice as long, so under a high update rate the
  2,048-record cap is reached sooner. The memory bound itself is unchanged.

### Neutral / Operational

- A restart drops every session, as before, so a round 2 that follows one goes
  to the graced timeout lane, as it already did.

## Validation

- `several_updates_between_the_rounds_do_not_fail_an_honest_holder`: three
  updates between the rounds fail with `DigestMismatch` before this change and
  pass after it, and round 2 serves exactly the record round 1 read.
- `round_two_serves_the_record_round_one_read_across_several_updates` (e2e):
  both rounds sent over QUIC to a live node, with three updates between them.
  It fails if the node stops handing round 1's roots to its session.
- `a_bound_record_no_longer_held_is_unavailable_not_failed`,
  `without_the_bound_root_a_pointer_is_unavailable_not_failed`,
  `subtree_session_carries_pointer_bindings_within_the_budget`,
  `past_the_cap_the_oldest_replaced_record_anywhere_goes_first` and
  `a_replaced_record_outlives_the_slowest_audit` cover the limits above.
- In production, a pointer holder's `DigestMismatch` rate should not rise with
  the update rate of the pointers it holds. A rise in `Transient` round-2
  rejections naming a pointer means the retention or session budget is being
  reached.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human
review**. Accepted ADRs are immutable: create a new superseding ADR rather than
editing an Accepted ADR.
