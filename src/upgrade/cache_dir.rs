//! Shared cache directory for upgrade artifacts.
//!
//! Multiple ant-node instances on the same machine share a single cache
//! directory so that release metadata and downloaded binaries are fetched only
//! once, reducing GitHub API calls and bandwidth.

use crate::error::{Error, Result};
use std::fs;
use std::path::PathBuf;

/// Return the shared upgrade cache directory, creating it on demand.
///
/// The path is `{data_dir}/upgrades/` where `data_dir` comes from
/// `directories::ProjectDirs` (e.g. `~/.local/share/ant/upgrades/` on
/// Linux).
///
/// # Errors
///
/// Returns an error if the platform data directory cannot be determined or
/// the directory cannot be created.
pub fn upgrade_cache_dir() -> Result<PathBuf> {
    let project_dirs = directories::ProjectDirs::from("", "", "ant").ok_or_else(|| {
        Error::Upgrade("Cannot determine platform data directory for upgrade cache".to_string())
    })?;

    let cache_dir = project_dirs.data_dir().join("upgrades");
    fs::create_dir_all(&cache_dir)?;

    // Defence in depth: restrict the shared upgrade cache to the owning
    // user (0700) so a co-located low-privilege process cannot
    // write/tamper with cached archives in the first place. The ML-DSA
    // re-verification on every cache hit is the primary control; this just
    // shrinks the attack surface. Best-effort on Unix; a failure to tighten
    // permissions must not break upgrades (the crypto gate still holds).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(&cache_dir) {
            let mut perms = meta.permissions();
            perms.set_mode(0o700);
            if let Err(e) = fs::set_permissions(&cache_dir, perms) {
                crate::logging::warn!(
                    "Could not tighten upgrade cache dir permissions to 0700 ({e}); \
                     ML-DSA re-verification still protects cached archives"
                );
            }
        }
    }

    Ok(cache_dir)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Verify the function succeeds and returns a path ending in "upgrades".
    ///
    /// Note: this creates a real directory under the platform data dir.
    /// Modifying env vars to isolate this requires `unsafe` (due to
    /// `deny(unsafe_code)`), so we accept the minor side-effect.
    #[test]
    fn test_upgrade_cache_dir_returns_path() {
        let dir = upgrade_cache_dir().unwrap();
        assert!(dir.exists());
        assert!(dir.ends_with("upgrades"));
    }
}
