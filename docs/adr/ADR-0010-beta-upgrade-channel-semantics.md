# ADR-0010: Restrict the beta upgrade channel to `-beta.*` pre-releases

- **Status:** Proposed
- **Date:** 2026-08-18
- **Decision owners:** @jacderida
- **Reviewers:** @dirvine
- **Supersedes:** none
- **Superseded by:** none
- **Related:** Linear V2-1010, V2-1011, V2-1012; `src/upgrade/monitor.rs`

## Context

Nodes auto-upgrade by polling the GitHub releases list for `WithAutonomi/ant-node` and selecting the
highest-versioned release that matches their configured channel and carries both a platform binary
and its `.sig`. GitHub's own `prerelease` / `latest` flags are ignored; selection is driven purely by
semver on the tag.

Two channels exist: `stable` (the default) and `beta`, chosen per node with `--upgrade-channel` or
`ANT_UPGRADE_CHANNEL`. Their filters were:

- `Stable` — accept a version only if it has no pre-release component.
- `Beta` — accept everything.

The weekly release train publishes `vX.Y.Z-rc.N` as a GitHub prerelease on the Tuesday cut, *before*
the release gates have returned a verdict. "Beta accepts everything" therefore had two consequences
that only become visible once a beta channel has real users:

1. **The upgrade mechanism bypassed the release gates.** Every beta node would install the rc the
   moment it was published, which is the precise window in which the build is not yet known to be
   good. The gate process cannot be a control if the fleet installs the artefact before it runs.
2. **Beta soaks could not hold.** Semver orders pre-release identifiers lexically, so
   `0.17.0-beta.1 < 0.17.0-rc.1 < 0.17.0`. A node deliberately soaking `0.17.0-beta.1` would see the
   *next* cut's `-rc.1` as an upgrade and abandon the soak build for un-gated code.

The fix had to land before the first `v*-beta.N` tag was ever published, so that any node opting into
beta has correct semantics from its first poll. There is no way to retrofit semantics onto nodes that
have already shipped with the permissive rule.

## Decision Drivers

- The release gate must be the only thing that promotes code to the fleet; no channel may route
  around it.
- A soak is only meaningful if the build under soak is not silently replaced.
- The rule is applied in two code paths and must not be able to drift between them.
- Whatever is chosen becomes the compatibility contract for community beta nodes on day one.

## Considered Options

1. **Keep `Beta => true`.** No work. Retains both problems above; not viable once beta has users.
2. **Beta accepts finals plus pre-releases whose first identifier is exactly `beta`.** Everything
   else, `rc.*` included, is rejected on both channels.
3. **Add a third `rc` channel** so release candidates have a home and beta excludes them.

## Decision

We will adopt option 2. A version is eligible for a channel iff:

- its pre-release component is empty (a final release) — eligible on **both** channels; or
- its first dot-separated pre-release identifier is exactly `beta` (`0.17.0-beta.1`, `0.17.0-beta`)
  — eligible on **beta only**.

Every other pre-release suffix — `rc.*`, `alpha.*`, and anything added later — is rejected on every
channel. Matching is on the exact first identifier rather than a prefix, so `betax.1` does not
qualify.

The rule is defined once, as a free function in `src/upgrade/monitor.rs`, and used by both the
selection path (`select_upgrade_from_releases`, which is what `check_for_updates` actually calls) and
the public `UpgradeMonitor::version_matches_channel`.

Option 3 is deliberately deferred rather than rejected: nothing here prevents adding an `rc` channel
later, and the exact-identifier rule means doing so is an additive change.

## Consequences

### Positive

- A release candidate cannot reach any node through the upgrade mechanism, so publishing the Tuesday
  cut no longer races the gate verdict.
- A beta node holds its soak build until a higher `-beta.N` or a final release appears.
- The rule exists in one place, so the selection path and the predicate cannot diverge.
- The `stable` channel is unchanged, so the production fleet is unaffected.

### Negative / Trade-offs

- **No channel installs release candidates any more.** Internal rc soaking, if wanted, must be done
  by deploying the binary directly or by introducing the `rc` channel from option 3. This is a real
  capability reduction and is the main thing a reviewer should weigh.
- Any future pre-release suffix is rejected by default. That is the safe direction, but it means a
  new suffix requires a deliberate code change rather than working implicitly.

### Neutral / Operational

- A node already running an rc under the old rule stays there until a higher eligible version is
  published; nothing forces it off.
- Asset naming, signature verification, and staged rollout are untouched.
- The releases page keeps its `prerelease` flag on beta tags, and the release workflow now sets
  `make_latest` explicitly so a pre-release can never be promoted to "Latest".

## Validation

- Unit tests in `src/upgrade/monitor.rs` cover: stable rejecting `-beta.N` and `-rc.N`; beta
  accepting `-beta.N` and finals while rejecting `-rc.N`, `-alpha.N` and `-betax.N`; selection over a
  mixed list (`0.16.0`, `0.17.0-beta.1`, `0.17.0-rc.1`) resolving to `0.16.0` on stable and
  `0.17.0-beta.1` on beta; and the ship-and-promote-same-day case hopping from `0.16.0-beta.1`
  straight to `0.17.0-beta.1`.
- End-to-end validation is tracked separately as V2-1012: a dev testnet where the cohort pulls a fake
  `-beta.N` release and demonstrably ignores a real rc published in the same window.
- Review trigger: revisit this ADR if a new pre-release suffix is introduced, if internal rc soaking
  becomes a requirement (option 3), or if channel selection stops being semver-on-tag.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted
ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
