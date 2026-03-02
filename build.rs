//! Build script for saorsa-node.

use std::process::Command;

fn main() {
    // Rerun if the git HEAD pointer changes (branch switch, detached HEAD, etc.)
    println!("cargo:rerun-if-changed=.git/HEAD");
    // Rerun if the current branch tip moves (new commits)
    println!("cargo:rerun-if-changed=.git/refs/heads");
    // Rerun if refs are packed (e.g. after `git gc`)
    println!("cargo:rerun-if-changed=.git/packed-refs");
    println!("cargo:rerun-if-changed=build.rs");

    let commit = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map_or_else(|| "unknown".to_string(), |s| s.trim().to_string());

    println!("cargo:rustc-env=SAORSA_GIT_COMMIT={commit}");
}
