# Prepare for Auto Upgrade Test

@Cargo.toml
@src/config.rs
@src/upgrade/monitor.rs
@src/node.rs
@.github/workflows/release.yml

I want you to help me prepare for a test of the automatic-upgrades process.

## Overview

The process has 4 phases:

* Derive test parameters from the current version
* Clear previous test artifacts
* Prepare the current branch for an auto-upgrade test
* Create a fake beta release branch and trigger the release

The fake release uses a `-beta.N` suffix, not `-rc.N`. The beta upgrade channel accepts a version
only when its pre-release component is empty or its first identifier is exactly `beta`; release
candidates are deliberately rejected on every channel, so an `-rc.1` fake release would never be
picked up by anything.

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
  `-beta.1` suffix) and prepending `beta-`. For example: `beta-0.3.12`.

Print the values you have obtained for these parameters and prompt me to verify them before
proceeding to the next phase.

# Phase 2: Clear Previous Test Artifacts

It's possible there was a previous test run that has not been cleaned up. We need to remove any
artifacts from any previous test.

Follow these steps for the current `BRANCH_NAME` / `TAG_NAME`:
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

# Phase 3: Preparing the Current Branch

For the test, the current branch needs a temporary commit that compresses the upgrade timing so
that test nodes detect and apply the fake beta release quickly.

Note that we do **not** change the default upgrade channel. Cohort nodes opt into beta explicitly
at launch with `--upgrade-channel beta` (or `ANT_UPGRADE_CHANNEL=beta`), exactly as a real
community beta node would, so the test exercises the real opt-in path.

The timing parameters are not runtime-configurable, so they have to be compiled in. This means the
tested binary is a modified build — a known and accepted limitation of a mechanism test.

Follow these steps:

* Compress the upgrade check interval from 1 hour to 20 minutes. The interval is currently held in
  hours as a `u64`, so it cannot express 20 minutes as a fraction. Convert the field to minutes:
  - Rename the `check_interval_hours` field in `UpgradeConfig` (`src/config.rs`) to
    `check_interval_minutes`, keeping the `u64` type.
  - Change `default_check_interval()` to return `20`.
  - In `UpgradeMonitor::new`, compute the interval as `check_interval_minutes * 60` seconds instead
    of `check_interval_hours * 3600`.
  - Update the serde field name and every other reference to `check_interval_hours` in the
    codebase, including tests.

* Change the staged rollout window from 24 hours to 2 hours for the test. Update
  `default_staged_rollout_hours()` in `src/config.rs` to return `2`. This keeps the test duration
  practical (100 nodes over 2 hours ≈ 1 restart/minute) while still validating even distribution.

* Create a chore commit with these changes. The commit message should indicate that these are
  temporary timing changes for auto-upgrade testing and will be removed after the test. Let me
  review the commit before proceeding.

* Push the change to the `origin` remote (the user's fork). Force pushing is fine if necessary.

# Phase 4: Create Fake Beta Release Branch

Now we need to create a fake beta release branch that will trigger a GitHub release when the tag is
pushed.

Follow these steps:

* Create a new branch from the current one called `BRANCH_NAME`.
* Update the `version` field in `Cargo.toml` to the value of `BETA_VERSION`.
* Put this change in a commit with the title `chore(release): fake beta release BETA_VERSION` and in
  the body, indicate that it's a fake beta release for testing automatic upgrades.

Allow me to review the commit, and once I approve:

* Push the branch to the `upstream` remote.
* Push the tag `TAG_NAME` pointing at the HEAD of this branch to the `upstream` remote. This will
  trigger the release workflow which builds, signs, and publishes the release as a pre-release on
  GitHub.

After pushing, print a reminder:
- The release workflow will take several minutes to complete.
- Once complete, the fake beta release will appear as a pre-release at
  `https://github.com/WithAutonomi/ant-node/releases`. It will not be marked "Latest".
- Test nodes must be running with `--upgrade-channel beta` (or `ANT_UPGRADE_CHANNEL=beta`) and the
  compressed-timing build from Phase 3; they will detect and upgrade to this version within
  ~20 minutes. Nodes left on the default stable channel will correctly ignore it.
- After testing, remember to clean up: revert the temporary commit on the current branch, and
  delete the beta branch/tag/release from upstream.
