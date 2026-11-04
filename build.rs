//! Build script for ant-node.

use std::path::Path;
use std::process::Command;

#[path = "build_support/git_watch.rs"]
mod git_watch;

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

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_support/git_watch.rs");

    // Watch only git paths that exist; see `git_watch::watch_paths` for why.
    if let (Some(git_dir), Some(common_dir)) = (
        git(&["rev-parse", "--git-dir"]),
        git(&["rev-parse", "--git-common-dir"]),
    ) {
        for path in git_watch::watch_paths(Path::new(&git_dir), Path::new(&common_dir)) {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }

    let commit = git(&["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=ANT_GIT_COMMIT={commit}");
}
