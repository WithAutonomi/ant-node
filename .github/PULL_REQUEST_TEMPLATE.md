## Linear issue
<!-- REQUIRED. Use a closing magic word + the issue key, one line per issue:

         Closes V2-123

     Any of Linear's closing words works, in any tense — close / fix / resolve /
     complete / implement, plus their -s, -d and -ing forms, and the phrase
     `linear issue`. The key may be a linear.app/<workspace>/issue/<key> URL.

     The closing form is what makes Linear attach the PR to the issue and move
     the issue to Merged when this lands on main. A bare `V2-123` does NOT link
     the PR — Linear ignores it — so CI rejects it. Linear's linking-only words
     (`ref`, `part of`, `towards`, `relates to`) do attach the PR but do not
     drive the Merged transition, so CI does not accept those either. (An issue
     key in the branch name or the PR title also links the PR, but write the
     closing form here anyway.) -->

## Risk tier
<!-- Check exactly one. Boundary question: does this change node behavior, the wire
     protocol, stored-data format, payments/economics, or the upgrade mechanism?
     If yes -> T2/T3, and it rides the weekly release train.
     If no  -> T0/T1, and it may ship via the client track.
     Propose the tier; a human confirms it at review. -->
- [ ] T0 — docs / tooling / CI / pure UX-output. Repo CI only.
- [ ] T1 — client-only, no network-facing behavior change. CI + prod compat smoke.
- [ ] T2 — node/client logic with behavioral surface, no protocol/format/economics change. Dev testnet + ADR.
- [ ] T3 — protocol / storage format / payments / routing. T2 evidence + adversarial testing.

## Compatibility
<!-- State the impact on each axis, or "none". -->
- Wire:
- Storage:
- API:

## Semver impact
<!-- Check exactly one. This is where the crate's bump level is decided, while the
     context is fresh; the train-manifest skill maps it to a per-crate version bump. -->
- [ ] breaking
- [ ] feature
- [ ] fix

## Test evidence
<!-- Per the tier: what was run, at what scale, and the result. Attach or link artifacts. -->

## New dependency
<!-- Any new external dependency? Write "none", or list them. New deps need explicit
     human acknowledgement in review. -->

## ADR
<!-- REQUIRED for Tier 2/3 — link the ADR. Write "n/a" for Tier 0/1. -->

## Mitigation / rollback
<!-- One line: how we back this out or limit the blast radius if it misbehaves. -->
