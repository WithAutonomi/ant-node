//! Shared cache directory for upgrade artifacts.
//!
//! Multiple saorsa-node instances on the same machine share a single cache
//! directory so that release metadata and downloaded binaries are fetched only
//! once, reducing GitHub API calls and bandwidth.

use crate::error::{Error, Result};
use std::fs;
use std::path::PathBuf;

/// Return the shared upgrade cache directory, creating it on demand.
///
/// The path is `{data_dir}/upgrades/` where `data_dir` comes from
/// `directories::ProjectDirs` (e.g. `~/.local/share/saorsa/upgrades/` on
/// Linux).
///
/// # Errors
///
/// Returns an error if the platform data directory cannot be determined or
/// the directory cannot be created.
pub fn upgrade_cache_dir() -> Result<PathBuf> {
    let project_dirs = directories::ProjectDirs::from("", "", "saorsa").ok_or_else(|| {
        Error::Upgrade("Cannot determine platform data directory for upgrade cache".to_string())
    })?;

    let cache_dir = project_dirs.data_dir().join("upgrades");
    fs::create_dir_all(&cache_dir)?;

    Ok(cache_dir)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_upgrade_cache_dir_returns_path() {
        let dir = upgrade_cache_dir().unwrap();
        assert!(dir.exists());
        assert!(dir.ends_with("upgrades"));
    }
}
