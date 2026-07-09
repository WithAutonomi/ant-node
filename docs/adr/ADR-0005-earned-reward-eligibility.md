# ADR-0005: Earned reward eligibility

- **Status:** Proposed
- **Date:** 2026-07-10
- **Decision owners:** Anselme (@grumbach)
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0002 (gossip-triggered contiguous-subtree storage audit — the work this ADR reads), ADR-0003 (full-node detection and eviction — the trust/eviction lane), ADR-0004 (commitment-bound quote pricing — bounds the per-payment cheat window this ADR builds on)

## Framing: earned future eligibility, not slashing

This ADR is an **incentive to keep serving**, layered on the network's existing
lost-trust model. It gates a node's eligibility for **future** rewards on a record
of useful storage work. It does **not** slash, claw back, or remove any settled
payment, and it introduces no new penalty on-chain. The only thing a node can lose
is the *opportunity to be paid next time*, until it has earned it back. "Caught
cheating" here means "this observer stops vouching for you until you re-earn a
week," never "money is taken from you."

## Context

ADR-0004 shrank the window in which a node can cheat on a single payment to
minutes. But a node's identity is just a free keypair: join, cheat, get caught,
throw the identity away, rejoin clean. A hit-and-run costs nothing to repeat.

What's missing is a **sunk cost**: real work a node must put in before it can be
paid, so abandoning an identity means abandoning that work. This ADR makes that
work "roughly a week of storing real data and passing audits on it."

We do this without three things we deliberately rule out: **no fee to join** (it
would destroy node operator UX), **no new blockchain machinery** (the chain stays
a payment rail), and **no reputation score**. A score is a complexity bomb: its
thresholds quietly break as the network's audit rate drifts, and a subjective
rating is a bad thing to gate money on. Instead we count plain facts: how many
times a node passed an audit, and when.

## Decision

**A node must earn its place before it can be paid**: about a week of audited
storage at the size it wants to charge for. Only clients enforce this, by
choosing who they pay; nodes and the chain are unchanged.

- **Each node keeps a simple record of what it audited.** Every node already
  audits its neighbours (ADR-0002/0004). It now writes down the result: for each
  peer, how many audits it passed each day, and the largest amount of data it
  proved it was holding. These are plain counts, saved to disk like any other
  network state, nothing weighted or decayed, nothing to tune. Two things can
  knock a peer's record down. If a node is *caught cheating* (a failed audit) its
  record is wiped and it has to start the week over; that mark sticks for the full
  week even as new passes come in, so getting caught costs exactly one week's
  re-earning, never a permanent ban. If a node simply *goes quiet* on data it was
  paid to keep, its record stops counting until it answers an audit again: silence
  costs it one vouch for as long as it lasts, and nothing more.

- **When a node quotes a price, it also shares what it has witnessed.** A quote
  reply now carries the node's own audit record for the peers near that address:
  positive facts only, no accusations about anyone. It's signed, and tied to a
  fresh random token the client puts in each request, so an old record can't be
  replayed. Quote replies are the only place these records travel; they're never
  passed along in a payment, and no node ever acts on another node's record.

- **The client decides who's eligible, from those shared records.** A node's
  judges are the *other* nodes that answered the same quote request; a node never
  vouches for itself. This set is exactly the responders to one request, not a
  standing neighbourhood or "anyone who ever audited it" — and it rotates per
  address, so an attacker cannot pre-position where its judges will be. Among the
  judges that have any record of the node, it is eligible when **more than half of
  them vouch for it** (but never fewer than 3 judges). A judge vouches when its
  record shows the node passed audits on at least ~7 different days in the last two
  weeks, at the size being quoted (with some slack), with the most recent pass
  inside the last day. That last-day requirement is kept alive by the node's
  routine hourly commitment refresh, which re-gossips a freshly signed commitment
  and draws a fresh audit whether or not the node took in any new data, so an
  honest node that is simply idle does not fall out of eligibility. Judges with no
  record of the node simply abstain: a brand-new or just-arrived neighbour neither
  helps nor hurts, so there's no knob to tune for them.

- **A majority, not a fixed count.** The rule cuts both ways: to exclude a node,
  more than half its judges must decline to vouch, meaning it was genuinely caught
  by half the neighbourhood, or half the neighbourhood is colluding, which is the
  same "capture the neighbourhood" bar the network already lives with elsewhere. A
  fixed count of vouches would not do this: a node caught by nearly half its judges
  could still clear a small fixed bar, whereas a majority scales the exclusion to
  the size of the neighbourhood that actually watched it.

- **The check happens when the client gathers quotes, not when it pays.** The
  client already asks more nodes than it needs; it now prefers eligible ones when
  filling its list. If not enough are eligible (which fast, network-wide growth can
  cause, since nobody has a full week at the newly grown size), it prefers the
  nodes with the most dues done, a clean audited week at any size, before falling
  back to today's ungated rules. Falling back is a degraded-security mode, not a
  neutral one — earned eligibility is being bypassed — so it is logged and surfaced
  as a metric, letting operators see how often and where the network is running
  ungated. This keeps out the two things the gate is for, fresh identities and
  caught cheaters, even when it cannot enforce size, and ADR-0004 still forces a
  current-size proof at payment. How the winning payee is chosen and how payment is
  verified do not change at all: if the whole list is eligible, whoever wins is
  eligible.

- **Nodes that aren't yet eligible still store data.** That unpaid storage *is* the
  week of dues, and nodes already store for their neighbourhood without being paid
  for every chunk.

- **This leans on ADR-0004.** ADR-0004 already forces an audit on any data a node
  got paid to keep, on top of the random ones, and already treats a wrong answer
  there as a definite cheat. This ADR just records those outcomes: a wrong answer
  wipes the record, a silent one freezes it. So the fastest, most certain
  detections land exactly on the data a node was paid to keep: the forced audit
  needs no lottery, and it's the other nodes storing alongside the payee that run
  it. A node that takes payment and then deletes fails that audit every time, so
  "caught" marks pile up across the neighbourhood fast, while its old vouches age
  out.

- **Newcomers can't be frozen out by incumbents.** A node is judged only on its
  own record, never ranked against others, so a newcomer earns its place even when
  the existing neighbours are "old friends" who might prefer to keep it out. One
  node abstaining can never keep anyone out.

## Policy reference (the client aggregation rule, written out)

So that clients and nodes share one exact meaning, the eligibility predicate a
client evaluates over the signed reports it collected is:

- **Reporters (judges).** The other nodes that answered this client's quote
  request for this address. The subject is never its own judge (self-vouch is
  discarded). Reporters rotate per address by construction.
- **Opinions vs abstention.** A reporter is an *opinion* only if its report carries
  a row for the subject; a reporter with no row **abstains** and is neither in the
  numerator nor the denominator. Abstention can never suppress a node.
- **Vouch (numerator).** A reporter's row vouches when it is unfenced, unconvicted,
  and shows ≥ **D** distinct days (default 7), each carrying at least one pass at a
  proven size that covers the quoted size within a **slack** factor (default 2×),
  all inside a trailing **window** (default 14 days), with the most recent covering
  day no older than the **recency** bound (default 1 day).
- **Bar.** Eligible when vouches > half of opinions, floored at **3** opinions
  (`bar = max(3, opinions/2 + 1)`). Fewer than 3 opinions → cannot be size-eligible
  on this rule alone; it falls to the dues tier / ungated fallback below.
- **`fenced`.** Set by a monetized-pin audit timeout on the reporting node; a
  fenced row does not vouch until the subject passes a fresh audit, at which point
  it clears. A fence is that one observer's withheld vouch — never portable guilt.
- **`convicted`.** Set by a *confirmed* (non-timeout) subtree-audit failure. It
  zeroes the day history and stays **sticky for the dues period D** even as fresh
  passes accrue underneath, so one catch costs exactly one week's re-earning and
  never compounds into a permanent ban. (Node and protocol MUST agree on this
  sticky semantics — a convicted row does *not* clear on the next pass.)
- **Newcomer / reset path.** A node with no history simply isn't yet size-eligible;
  it is not marked malicious. Under the two-tier fallback it can still be selected
  via the dues tier (a clean audited week at any size) or the ungated fallback, so
  honest new and churned-in nodes are never frozen out. Suppressing a qualified
  newcomer requires more than half its judges to lie, i.e. neighbourhood capture.
- **Missing / invalid reports.** Distinguished and handled as: *not upgraded* (no
  report field) and *no testimony* (report present, no row) → abstain;
  *unreachable* → not a reporter; *invalid* (bad signature, wrong nonce, over-cap)
  → dropped before parse, contributes nothing; *fenced* / *convicted* → counted as
  a non-vouching opinion (in the denominator, not the numerator).

## Consequences

**Positive**
- Walking away from an identity throws away ≈ a week of real, audited storage;
  parked or empty nodes earn nothing.
- No reputation score to tune into a fragile equilibrium: standing is plain counts
  a human can read ("passed audits all week at this size"), and the client-side
  settings can be adjusted without shipping new node software.
- The network never stalls: data is always stored, and if too few nodes are
  eligible, which can happen under fast network-wide growth or heavy churn,
  payments fall back to the most dues done and then to today's behaviour.

**Negative / trade-offs**
- Honest new nodes earn nothing for their first ≈ week. This will need clear
  operator messaging. Nodes that grow fast wait a little longer for full-size
  eligibility, since the size has to have been held for the week too, though the
  dues fallback still lets them earn in the meantime.
- **Some settings are client-side, some aren't.** The client can freely retune the
  ~7-day requirement, the size slack, the recency window, and the enforce switch.
  But the two-week memory window and how long a "caught" mark sticks are baked into
  the node software, so changing *those* needs a node release. This is the one
  partial exception to "nothing to tune": if audit cadence drifts far enough, those
  two constants would need re-fitting in a release rather than as client policy.
- **A node's shared record has a size limit.** It reports on at most a couple dozen
  peers, preferring the most recently active. In a big or fast-churning
  neighbourhood that can silently leave some peers out of a given report, which
  turns those judges into abstainers and makes the "more than half" count harder to
  reach. An unlucky node could dip out of eligibility for a spell, but its next
  audits put it straight back on the reports, so any such dip is brief and
  self-correcting.
- **Reports are testimony, not proof.** A signed row is a reporter's own claim; it
  carries no portable audit proof a third party could re-verify. The defence
  against colluding reporters is structural, not cryptographic: the judges are the
  per-address responder set (not attacker-chosen), self-vouch is excluded, and the
  majority bar means smuggling a cheater in or freezing an honest node out both
  require capturing more than half that set — the same neighbourhood-capture
  boundary ADR-0004's median already accepts.

**Neutral / operational**
- Each quote reply grows by the shared record: ~7 KB at a ~20-peer neighbourhood,
  hard-capped at 16 KB; an over-cap report is dropped whole, never trimmed on the
  wire. The producing node enforces the row, day, and serialized-byte caps before
  emitting a report, so an over-cap report is never put on the wire. A single
  upload gathers one report per quote responder, about 7 while the gate is only
  observing and up to ~20 once it is enforcing; a batched "merkle" upload gathers
  up to ~32, one from each node it over-queries. All of it stays on the client.
- **Hard wire cutover.** The new quote-request nonce and quote-response report
  fields change the wire format. Because the shared payment types are
  postcard-encoded (non-self-describing), old and new peers do not interoperate, so
  this ships as a coordinated cutover with a bumped protocol identifier / version —
  not a mixed-fleet rollout. Nodes that don't upgrade lose access to rewards, so
  the incentive to migrate is built in.
- **Day length is fixed in production.** The tally's notion of "a day" is a fixed
  86400 seconds in any release build; the compressed-time knob used by local
  testnets is compiled out (feature-gated) so a reporter can never redefine "a day"
  in production eligibility evidence.
- Recommended starting values, to be finalised against real production numbers:
  ~7 audited days required, two-week memory window, most-recent pass within ~1 day,
  size slack ~2×, majority of judges with a floor of 3, "caught" mark sticks ~7
  days.
- Rolled out in stages: nodes start keeping and sharing the record, then clients
  watch and log who they *would* exclude (observe-only shadow eligibility, to
  calibrate against churn / NAT / newcomer cases), then clients turn enforcement on
  only once that data looks right.

## Validation

This decision is correct only if the following hold; each must be shown before the
ADR is Accepted:

- **Honest nodes qualify and stay eligible.** A node storing real data qualifies in
  about a week, an honest node that holds steady data without new uploads does not
  quietly fall out of eligibility, and enforcement causes no upload failures.
- **Cheaters are excluded quickly.** A node that takes payment and then deletes is
  dropped within about a day of its first payment, whether or not it keeps
  receiving fresh data afterward.
- **Fence and conviction behave as specified.** A monetized-pin timeout fences and
  clears on the next pass; a confirmed failure convicts and stays sticky for the
  dues period even as passes accrue; a restart preserves the tally safely.
- **Collusion is as hard as capturing a neighbourhood.** Withholding vouches or
  faking catches can only exclude an honest node, or keep a cheater in, by
  controlling more than half its judges: the same bar the network already accepts
  for pricing and audits.
- **The audit cadence in production actually supports the ~7-day rule**, measured on
  the real fleet under observe-only shadow eligibility before enforcement is turned
  on.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human
review**. Accepted ADRs are immutable: create a new superseding ADR rather than
editing an Accepted one.
