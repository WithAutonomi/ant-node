# Prepare for Musl Swap Auto-Upgrade Test

@Cargo.toml
@src/config.rs
@src/upgrade/monitor.rs
@src/upgrade/apply.rs
@src/node.rs
@.github/workflows/release.yml

I want you to help me prepare for a test of the automatic-upgrades process where a beta release
switches the Linux build from glibc to musl. The initial testnet runs glibc binaries (today's
production shape); the beta release publishes musl-static binaries under the same asset filenames
so the existing substring matcher picks them up.

The fake release uses a `-beta.N` suffix, not `-rc.N`. The beta upgrade channel accepts a version
only when its pre-release component is empty or its first identifier is exactly `beta`; release
candidates are deliberately rejected on every channel, so an `-rc.1` fake release would never be
picked up by anything.

## Branch model

There is a shared **feature base** and three branches built from it. Be careful not to conflate
them.

**Feature base.** The branch containing the upgrade-subsystem changes that are actually under test
— currently `grumbach/fix/a1-upgrade-cache-resign-verify` (per-cache-hit ML-DSA re-verification,
FIFO/pipe rejection, cache-first apply ordering). Both the test branch and the musl swap branch
**must** be based on this, so the initial-cohort binary and the beta binary share identical
upgrade-apply code. If they don't, the running (initial) binary may short-circuit before reaching
the code path the test is trying to exercise — e.g. an old version-check-first ordering never
consults the cache, so sibling nodes never hit the re-verification path. Ask me which branch is
the current feature base; it changes per test.

1. **Test branch** (e.g. `chore/musl-swap-upgrade-test`). Cut from the **feature base**. The only
   change on top is a temporary commit that shortens the upgrade check interval and staged rollout
   window so initial nodes detect and apply the beta release quickly. It does **not** change the
   default upgrade channel — cohort nodes opt into beta explicitly at launch (see Phase 3).
   **The test branch does NOT contain the musl swap or mimalloc** — the whole point of the test is
   that the initial cohort runs the current production shape (glibc) and upgrades to a musl beta
   release. Discarded after the test.

2. **Musl swap branch** (e.g. `feat/musl-linux-builds`). The feature base **plus** the *real*
   product change being tested: flipping the release workflow's two Linux matrix entries from
   `gnu` to `musl`, plus the `mimalloc` global allocator. Intended to land on `main` eventually as
   a normal PR. **Not** thrown away after the test.

3. **Fake beta branch** (`BRANCH_NAME` from Phase 1). Cut from the musl swap branch. The only
   thing it adds is the version bump to `BETA_VERSION`. Discarded after the test along with the tag
   and pre-release.

Tag the fake beta branch and you get a pre-release that contains musl-built Linux binaries. The
test branch's (glibc) initial nodes, started on the beta channel, detect that release and upgrade
to it. Because both branches share the feature base, the only intended differences between the
initial and upgraded binaries are: timing (test branch) and musl + mimalloc (beta release).

## Overview

The process has 6 phases:

* Derive test parameters from the current version
* Clear previous test artifacts
* Prepare the test branch (timing commit — glibc initial nodes)
* Prepare the musl swap branch (release workflow gnu → musl + mimalloc)
* Create the fake beta branch (musl swap branch + version bump)
* Publish to upstream and verify

# Phase 1: Derive Test Parameters

We need to derive all test parameters from the current `Cargo.toml` version.

Follow these steps:
- Read the current version from `Cargo.toml` (the `version` field under `[package]`).
- Create a `BETA_VERSION` parameter by adding 10 to the current PATCH component and appending a
  `-beta.1` suffix. For example, if the current version is `0.3.2`, the beta version should be
  `0.3.12-beta.1`.
- Create a `TAG_NAME` parameter by prepending `v` to the `BETA_VERSION`. For example:
  `v0.3.12-beta.1`.
- Create a `BRANCH_NAME` parameter by taking the version with the bumped patch (without the
  `-beta.1` suffix) and prepending `beta-`. For example: `beta-0.3.12`. This is the *fake beta*
  branch.

Ask me for:
- the **feature base** branch (the upgrade-subsystem branch under test, e.g.
  `grumbach/fix/a1-upgrade-cache-resign-verify`) — run `git fetch` on its remote so it's current;
- the **test branch** name;
- the **musl swap branch** name.

None of these are derived from the version. The feature base and musl swap branch may already
exist from a previous session; in that case I'll point you at them.

Print the values you have obtained for these parameters and prompt me to verify them before
proceeding to the next phase.

# Phase 2: Clear Previous Test Artifacts

It's possible there was a previous test run that has not been cleaned up. We need to remove any
artifacts from any previous test.

The musl swap branch is a real branch that may persist across test runs — do **not** delete it in
this phase. Only the fake beta branch and its tag/release are throwaway.

Follow these steps:
- If a `BRANCH_NAME` branch exists locally, delete it.
- If a `BRANCH_NAME` branch exists on the `upstream` remote, delete it.
- If a `TAG_NAME` tag exists locally, delete it.
- If a `TAG_NAME` tag exists on the `upstream` remote, delete it.
- If a GitHub release exists for `TAG_NAME` on the upstream repository (`WithAutonomi/ant-node`),
  delete it using `gh release delete TAG_NAME --repo WithAutonomi/ant-node --yes`.

Earlier runs of this command used release-candidate names, so also clean up the legacy equivalents:
- The `rc-<bumped version>` branch, locally and on `upstream` (e.g. `rc-0.3.12`).
- The `v<bumped version>-rc.1` tag, locally and on `upstream` (e.g. `v0.3.12-rc.1`).
- The GitHub release for that rc tag, if one exists.

For each step, check if the artifact exists before attempting deletion. Report what was cleaned up.

# Phase 3: Prepare the Test Branch (glibc initial nodes)

The test branch is what the initial testnet nodes are built from. They MUST stay glibc — the whole
point of the test is to verify that glibc nodes correctly download and execute the musl beta
binary. So the test branch only modifies upgrade timing; **it does not touch
`.github/workflows/release.yml` or add mimalloc** — those belong only on the musl swap branch.

We do **not** change the default upgrade channel. Cohort nodes opt into beta explicitly at launch
with `--upgrade-channel beta` (or `ANT_UPGRADE_CHANNEL=beta`), exactly as a real community beta
node would. The timing parameters are not runtime-configurable, so those still have to be compiled
in — a known and accepted limitation of a mechanism test.

Switch to the test branch I named in Phase 1.

- If the branch already exists (locally or on `origin`) and already has the timing commit sitting
  directly on top of the **feature base**, skip the modification steps and proceed to the push
  step. If it still carries an older commit that moved the `#[default]` upgrade channel to `Beta`,
  drop that part — the channel is now selected per node at launch.
- If the branch does not exist anywhere, create it from the **feature base** (the upgrade-subsystem
  branch named in Phase 1, e.g. `grumbach/fix/a1-upgrade-cache-resign-verify`). **Not from
  `upstream/main` and not from the musl swap branch.** The test branch must carry the same
  upgrade-apply code as the beta build (so the path under test is reachable on the running binary)
  while staying glibc (so the test exercises a real glibc → musl swap). If the feature base is just
  `upstream/main` for a given run (no separate upgrade changes under test), cutting from
  `upstream/main` is correct — confirm with me.

Then apply these changes:

* Compress the upgrade check interval from 1 hour to 20 minutes. The interval is held in hours as
  a `u64`, so it cannot express 20 minutes as a fraction — convert the field to minutes:
  - Change the `check_interval_hours` field in `UpgradeConfig` (`src/config.rs`) to
    `check_interval_minutes` (type `u64`).
  - Update `default_check_interval()` to return `20` (minutes).
  - Update `UpgradeMonitor::new` (in `src/upgrade/monitor.rs`) to calculate
    `check_interval_minutes * 60` instead of `check_interval_hours * 3600`.
  - Update the serde field name and any references to `check_interval_hours` throughout the
    codebase.

* Change the staged rollout window from 24 hours to 2 hours. Update
  `default_staged_rollout_hours()` in `src/config.rs` to return `2`.

* Create a single chore commit with these changes. The commit message should indicate that these
  are temporary timing changes for an auto-upgrade musl swap test and will be reverted after the
  test. Let me review the commit before proceeding.

* Push the change to the `origin` remote (the user's fork). Force pushing is fine if necessary.

# Phase 4: Prepare the Musl Swap Branch (release workflow gnu → musl)

This branch holds the *real* product change — flipping the release workflow's Linux matrix from
`gnu` to `musl` and adding `mimalloc` as the global allocator. It will be opened as a normal PR
after the test passes; it is not throwaway. The fake beta branch (Phase 5) is cut from this
branch.

Switch to the musl swap branch I named in Phase 1.

- If the branch already exists (locally or on `origin`) and already contains the workflow change
  and the mimalloc commit on top of the **feature base**, skip the modification and commit steps
  and proceed straight to the push step (which is a no-op if `origin` is already up to date).
- If the branch does not exist anywhere, create it from the **feature base** (the same branch the
  test branch is cut from) — **not from `upstream/main`** when a separate feature base is in play.
  The musl swap branch and the test branch must share the same upgrade-apply code.

If creating from scratch, apply two commits:

1. Modify `.github/workflows/release.yml` to build musl instead of glibc on Linux. In the build
   matrix:
   - Change the `x86_64-unknown-linux-gnu` row's target to `x86_64-unknown-linux-musl` and add
     `cross: true`.
   - Change the `aarch64-unknown-linux-gnu` row's target to `aarch64-unknown-linux-musl` (it
     already has `cross: true`).
   - **Do not change `friendly_name`, `binary`, or `archive`** — asset filenames must remain
     `ant-node-cli-linux-{arm64,x64}.tar.gz` so the existing substring matcher on running nodes
     still finds them. The contents change; the names do not.

2. Add `mimalloc = "0.1"` to `[dependencies]` in `Cargo.toml`. Add `#[global_allocator] static
   GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;` to `src/bin/ant-node/main.rs` and
   `src/bin/ant-devnet/main.rs`.

Two separate commits with clear messages (these will eventually be on the PR). Let me review
before pushing.

Push the musl swap branch to `origin`.

# Phase 5: Create the Fake Beta Branch (version bump only)

Cut `BRANCH_NAME` from the **musl swap branch** (Phase 4), **not from the test branch**. The beta
build must not carry the timing tweak — that change only belongs on initial nodes. This branch's
tag triggers the release. It is thrown away after the test.

Follow these steps:

* Switch to the musl swap branch from Phase 4 and confirm you're on it.
* Create a new branch `BRANCH_NAME` from it.
* Update the `version` field in `Cargo.toml` to the value of `BETA_VERSION`.
* Commit with the title `chore(release): fake beta release BETA_VERSION` and a body noting it's a
  fake beta release for testing the glibc → musl auto-upgrade swap.

Allow me to review the commit, and once I approve, proceed to Phase 6.

# Phase 6: Publish to Upstream and Verify

Now publish to upstream and run the verification.

Follow these steps:

* Push the `BRANCH_NAME` branch to `upstream`.
* Push the `TAG_NAME` tag to `upstream`. This triggers the release workflow on
  `WithAutonomi/ant-node` and produces the real test pre-release.

After pushing, print a reminder of the test plan:

**Rollback safety check (do before deploying any cohort):**
- Read `src/upgrade/apply.rs` and identify whether failed-upgrade rollback is implemented (e.g.
  does it keep the previous binary and restore it on spawn failure?). If rollback is absent, keep
  the cohort small enough to recover manually if a node fails to restart post-swap.

**Single-host smoke (run first):**
- On one glibc Ubuntu host, deploy a node from the test branch (glibc binary), started with
  `--upgrade-channel beta` (or `ANT_UPGRADE_CHANNEL=beta`). Confirm the channel is actually set
  before waiting — a node left on the default stable channel will correctly ignore the beta release
  and the wait will look like a failure.
- Wait for the upgrade interval (~20 min) and confirm the node picks up the beta release, swaps to
  the musl binary, restarts, and resumes serving.
- Verify the swapped binary is musl-static:
  ```sh
  readelf -l <node-data-dir>/ant-node | grep INTERP || echo "static musl"
  ```
  Glibc shows `/lib/ld-linux-{aarch64,x86-64}.so.{1,2}` after `INTERP`; musl-static shows nothing
  and the `echo` fires.
- Confirm `ant node status` shows the new version, `stderr.log` is empty, and the live log shows
  DHT bootstrap re-completing and peers reconnecting.

**Full glibc testnet (run after smoke passes):**
- Deploy a testnet via the `saorsa-testnet-registry` MCP using nodes built from the test branch —
  all nodes glibc, all started on the beta channel.
- Wait for the upgrade interval. Nodes should upgrade themselves over the 2-hour staged-rollout
  window.
- Verify a sample of nodes with the `readelf` check above.

**Cleanup after the test:**
- Revert the Phase 3 commit on the test branch and force-push to `origin`.
- Delete `BRANCH_NAME` locally and from `upstream`.
- Delete `TAG_NAME` locally and from `upstream`.
- Delete the pre-release on `WithAutonomi/ant-node`
  (`gh release delete TAG_NAME --repo WithAutonomi/ant-node --yes`).
- **Do not delete the musl swap branch** — open it as a PR if the test passed.
