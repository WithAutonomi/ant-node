//! Build script for ant-node.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Runs `git` with `args` and returns its trimmed stdout, or `None` when git is
/// unavailable or the command fails (for example, outside a git checkout).
fn git(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Asks Cargo to rerun this script when `path` changes, but only if it exists.
///
/// Cargo treats a `rerun-if-changed` path that does not exist as changed on
/// every build, which reruns this script and recompiles the whole crate each
/// time. Hard-coded `.git/...` paths hit that in a git worktree (where `.git`
/// is a file) and in CI checkouts that have no `packed-refs`, so every
/// `cargo test --test X` rebuilt ant-node from scratch.
fn rerun_if_exists(path: &Path) {
    if path.exists() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // HEAD lives in the per-worktree git dir; branch refs live in the common
    // dir that all worktrees share. In a plain clone both are `.git`.
    if let Some(git_dir) = git(&["rev-parse", "--git-dir"]) {
        // Rerun if the HEAD pointer changes (branch switch, detached HEAD, etc.)
        rerun_if_exists(&PathBuf::from(git_dir).join("HEAD"));
    }
    if let Some(common_dir) = git(&["rev-parse", "--git-common-dir"]) {
        let common = PathBuf::from(common_dir);
        // Rerun if the current branch tip moves (new commits)
        rerun_if_exists(&common.join("refs").join("heads"));
        // Rerun if refs are packed (e.g. after `git gc`)
        rerun_if_exists(&common.join("packed-refs"));
    }

    let commit = git(&["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=ANT_GIT_COMMIT={commit}");
}
