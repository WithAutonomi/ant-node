//! Regression tests for the git paths `build.rs` asks Cargo to watch (V2-1828).
//!
//! Cargo reruns a build script when a `rerun-if-changed` path is newer than the
//! script's last run (scanning directories recursively), and treats a missing
//! path as changed on every build. The watch set therefore has to contain only
//! existing paths, and some watched path has to change whenever `HEAD` comes to
//! resolve to a different commit, or `ANT_GIT_COMMIT` goes stale.
//!
//! These drive real git repositories in a temporary directory, so they need
//! `git` on the PATH, as the build script itself does.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../build_support/git_watch.rs"]
mod git_watch;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, SystemTime};

/// Runs git in `dir` with a fixed identity and no signing, panicking on failure.
fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .args([
            "-c",
            "user.name=ant-node test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .expect("git is installed");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// A repository in a temporary directory with one commit on `main`.
fn repo() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("repo");
    fs::create_dir(&dir).unwrap();
    git(&dir, &["init", "-q", "-b", "main"]);
    git(&dir, &["commit", "-q", "--allow-empty", "-m", "one"]);
    (tmp, dir)
}

/// The watch set as `build.rs` computes it when run from `dir`.
fn watch_paths_for(dir: &Path) -> Vec<PathBuf> {
    let resolve = |p: String| {
        let p = PathBuf::from(p);
        if p.is_absolute() {
            p
        } else {
            dir.join(p)
        }
    };
    let git_dir = resolve(git(dir, &["rev-parse", "--git-dir"]));
    let common_dir = resolve(git(dir, &["rev-parse", "--git-common-dir"]));
    git_watch::watch_paths(&git_dir, &common_dir)
}

/// The newest modification time of `path`, scanning directories recursively
/// as Cargo does for a `rerun-if-changed` directory.
fn newest_mtime(path: &Path) -> SystemTime {
    let meta = fs::metadata(path).unwrap();
    let mut newest = meta.modified().unwrap();
    if meta.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            newest = newest.max(newest_mtime(&entry.unwrap().path()));
        }
    }
    newest
}

fn newest_of(paths: &[PathBuf]) -> SystemTime {
    paths
        .iter()
        .map(|p| newest_mtime(p))
        .max()
        .expect("the watch set is not empty")
}

/// Waits out coarse filesystem timestamps, so a later write gets a later mtime.
fn tick() {
    sleep(Duration::from_millis(1100));
}

fn assert_all_exist(paths: &[PathBuf]) {
    assert!(!paths.is_empty(), "nothing is watched");
    for p in paths {
        assert!(
            p.exists(),
            "watch set contains a missing path: {}",
            p.display()
        );
    }
}

#[test]
fn a_commit_on_a_branch_changes_a_watched_path() {
    let (_tmp, dir) = repo();
    let paths = watch_paths_for(&dir);
    assert_all_exist(&paths);
    let before = newest_of(&paths);

    tick();
    git(&dir, &["commit", "-q", "--allow-empty", "-m", "two"]);

    assert!(
        newest_of(&paths) > before,
        "a commit changed no watched path"
    );
}

/// The case the first version of the fix missed: with every ref packed and no
/// `refs/heads` directory, the next commit creates `refs/heads/main` and leaves
/// both `HEAD` and `packed-refs` untouched.
#[test]
fn with_refs_packed_and_no_refs_heads_the_next_commit_is_still_seen() {
    let (_tmp, dir) = repo();
    git(&dir, &["pack-refs", "--all", "--prune"]);
    let heads = dir.join(".git").join("refs").join("heads");
    if heads.exists() {
        // pack-refs empties it; git recreates it on the next commit.
        fs::remove_dir(&heads).unwrap();
    }
    assert!(!heads.exists());

    let paths = watch_paths_for(&dir);
    assert_all_exist(&paths);
    assert!(
        !paths.contains(&heads),
        "the missing refs/heads must not be emitted"
    );
    let head = dir.join(".git").join("HEAD");
    let packed = dir.join(".git").join("packed-refs");
    let head_before = newest_mtime(&head);
    let packed_before = newest_mtime(&packed);
    let before = newest_of(&paths);

    tick();
    git(&dir, &["commit", "-q", "--allow-empty", "-m", "two"]);

    assert!(heads.join("main").exists(), "git recreated the loose ref");
    // This is what made the old watch set (HEAD, packed-refs) miss the commit.
    assert_eq!(newest_mtime(&head), head_before, "HEAD was not rewritten");
    assert_eq!(
        newest_mtime(&packed),
        packed_before,
        "packed-refs was not rewritten"
    );
    assert!(
        newest_of(&paths) > before,
        "the commit changed no watched path, so ANT_GIT_COMMIT would go stale"
    );
}

#[test]
fn in_a_worktree_every_watched_path_exists_and_a_commit_is_seen() {
    let (tmp, dir) = repo();
    let wt = tmp.path().join("wt");
    git(
        &dir,
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            "feature",
            wt.to_str().unwrap(),
        ],
    );
    assert!(wt.join(".git").is_file(), "a worktree's .git is a file");

    let paths = watch_paths_for(&wt);
    assert_all_exist(&paths);
    let before = newest_of(&paths);

    tick();
    git(&wt, &["commit", "-q", "--allow-empty", "-m", "two"]);

    assert!(
        newest_of(&paths) > before,
        "a worktree commit changed no watched path"
    );
}
