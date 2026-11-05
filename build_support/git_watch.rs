//! Which git paths the build script asks Cargo to watch, so that `ANT_GIT_COMMIT`
//! is refreshed whenever `HEAD` resolves to a different commit.
//!
//! Shared by `build.rs` and its regression test (`tests/build_script_git_watch.rs`)
//! through `#[path]`, because a build script can't have tests of its own.

use std::path::{Path, PathBuf};

/// The paths to pass to `cargo:rerun-if-changed`, given the per-worktree git
/// dir (`git rev-parse --git-dir`) and the common dir that all worktrees share
/// (`git rev-parse --git-common-dir`). In a plain clone both are `.git`.
///
/// Every returned path exists. Cargo treats a `rerun-if-changed` path that does
/// not exist as changed on every build, which reruns the build script and
/// recompiles the whole crate each time; hard-coded `.git/...` paths hit that
/// in a git worktree (where `.git` is a file) and in CI checkouts.
///
/// What is watched, and why:
/// * `HEAD` in the git dir. It changes on checkout or branch switch, and on
///   every commit when `HEAD` is detached.
/// * `refs/heads` in the common dir, which Cargo scans recursively. A commit on
///   a branch rewrites the loose ref file `refs/heads/<branch>`. When every ref
///   is packed the directory can be absent, and the next commit then *creates*
///   `refs/heads/<branch>` without touching `HEAD` or `packed-refs`. So when
///   `refs/heads` is missing, its nearest existing ancestor inside the common
///   dir (normally `refs`) is watched instead, which sees that file appear.
/// * `packed-refs` in the common dir, when present. It changes when refs are
///   packed or a packed ref is updated in place.
#[must_use]
pub fn watch_paths(git_dir: &Path, common_dir: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    let head = git_dir.join("HEAD");
    if head.exists() {
        paths.push(head);
    }

    let heads = common_dir.join("refs").join("heads");
    if let Some(existing) = heads
        .ancestors()
        .take_while(|p| p.starts_with(common_dir))
        .find(|p| p.exists())
    {
        paths.push(existing.to_path_buf());
    }

    let packed = common_dir.join("packed-refs");
    if packed.exists() {
        paths.push(packed);
    }

    paths
}
