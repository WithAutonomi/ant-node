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

### Amendment: a beta node skips its own promotion

Channel eligibility alone produced an unwanted hop. Semver ranks a final above its own
pre-release, so a node running `0.18.0-beta.1` treated the promoted `0.18.0` as an upgrade — a
binary swap and a network restart for what is the same code re-tagged. Because the train promotes
on every cycle, this would have happened on every train, to every beta node.

Eligibility is therefore refined: **on the beta channel, a final release is not a candidate when the
running version is a `beta.*` pre-release of the same `major.minor.patch`.** The skip is narrow by
design:

- A genuinely newer final is still taken (`0.19.0` while running `0.18.0-beta.1`), so a beta node
  does not stagnate if the beta line stalls.
- A later beta of the same version is still taken (`0.18.0-beta.2`).
- It applies to the beta channel only. A node running a beta build while configured for `stable`
  still takes the final, since that is its route back onto the stable line.

This is a rule about the *pair* (candidate, running version) rather than about the candidate alone,
so it lives beside the channel predicate rather than inside it.

The skip is safe because of how the train is shaped, not because the node can verify it. Promotion
does change the build: dependency references flip from git branch pins to published crates.io
versions (`ant-protocol = { git = ..., branch = "rc-2026.8.3" }` becomes `ant-protocol = "2.3.2"`),
so a final is not byte-identical to the beta it came from. What makes it the *same code* is that any
change landing on the RC branch produces a **new** beta release, and the final is promoted from the
most recent beta. There is therefore no window in which the final carries code that no beta carries.

Two consequences follow, and both matter:

- A node holding `X.Y.Z-beta.N` when `X.Y.Z-beta.N+1` and the final `X.Y.Z` are all published does
  not strand. The later beta is eligible and outranks the one it is running, while the final is
  skipped, so it converges on `beta.N+1` — the code that became the final. This depends on old beta
  releases remaining published after promotion, which is the current policy.
- The comparison must be against the build the node is **committed to**, not the one it is running.
  During a staged rollout those differ: a node that has selected `0.19.0-beta.1` but not yet applied
  it is still running `0.18.0-beta.1`, whose core differs from `0.19.0`. Comparing against the
  running version would let the final through and retarget the node onto it, so whether a node kept
  its beta identity would depend on where its rollout jitter happened to fall. Selection therefore
  takes the pending staged-rollout target when there is one.

The "is it newer" guard deliberately stays on the running version, so that a withdrawn pending
release cannot leave a node refusing everything still published.

## Consequences

### Positive

- A release candidate cannot reach any node through the upgrade mechanism, so publishing the Tuesday
  cut no longer races the gate verdict.
- A beta node holds its soak build until a higher `-beta.N` or a final release appears.
- The rule exists in one place, so the selection path and the predicate cannot diverge.
- The `stable` channel is unchanged, so the production fleet is unaffected.
- Beta nodes restart once per train rather than twice, and keep their identity as beta builds
  instead of being silently converted to stable ones on every promotion.

### Negative / Trade-offs

- **No channel installs release candidates any more.** Internal rc soaking, if wanted, must be done
  by deploying the binary directly or by introducing the `rc` channel from option 3. This is a real
  capability reduction and is the main thing a reviewer should weigh.
- Any future pre-release suffix is rejected by default. That is the safe direction, but it means a
  new suffix requires a deliberate code change rather than working implicitly.
- The skip depends on two properties of the release process that the node cannot verify: that any
  change after `beta.N` produces a `beta.N+1` which is what gets promoted, and that old beta
  releases stay published so a node on a stale beta can converge through them. Neither is
  mechanically enforced today; if either slips, a beta node holds an older build than it should.

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
  straight to `0.17.0-beta.1`. For the amendment: a beta node ignoring its own promotion, still
  taking a newer final, still taking a later beta of the same version, preferring the next beta over
  its own promotion, a stable-channel node still taking the promotion of a beta it is running, and a
  node holding its pending beta when that beta's final is published mid-rollout.
- End-to-end validation is tracked separately as V2-1012: a dev testnet where the cohort pulls a fake
  `-beta.N` release and demonstrably ignores a real rc published in the same window.
- Review trigger: revisit this ADR if a new pre-release suffix is introduced, if internal rc soaking
  becomes a requirement (option 3), or if channel selection stops being semver-on-tag.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted
ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
