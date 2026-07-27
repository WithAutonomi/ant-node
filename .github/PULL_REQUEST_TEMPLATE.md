## Linear issue
<!-- REQUIRED. Link the issue: an issue key like V2-123, or a linear.app URL.
     CI blocks PRs with no linked Linear issue. -->

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
