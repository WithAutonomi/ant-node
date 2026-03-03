//! Disk cache for downloaded upgrade binaries.
//!
//! When multiple saorsa-node instances detect the same upgrade, only the first
//! one needs to download and verify the archive.  `BinaryCache` stores the
//! extracted binary alongside a SHA-256 integrity metadata file so that
//! subsequent nodes can copy it directly.
//!
//! **Security note:** SHA-256 is used only for cache integrity (detecting
//! corruption or partial writes).  The actual security gate remains the
//! ML-DSA-65 signature verification performed during the initial download.

use crate::error::{Error, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use tracing::{debug, warn};

/// On-disk cache for downloaded upgrade binaries.
pub struct BinaryCache {
    /// Directory that holds cached binaries and metadata.
    cache_dir: PathBuf,
}

/// Metadata written alongside each cached binary.
#[derive(Serialize, Deserialize)]
struct CachedBinaryMeta {
    /// Semantic version string (e.g. "1.2.3").
    version: String,
    /// Hex-encoded SHA-256 digest of the cached binary.
    sha256: String,
    /// When the binary was cached (seconds since UNIX epoch).
    cached_at_epoch_secs: u64,
}

impl BinaryCache {
    /// Create a new binary cache backed by the given directory.
    #[must_use]
    pub fn new(cache_dir: PathBuf) -> Self {
        Self { cache_dir }
    }

    /// Return the path where a cached binary for `version` would be stored.
    #[must_use]
    pub fn cached_binary_path(&self, version: &str) -> PathBuf {
        let name = if cfg!(windows) {
            format!("saorsa-node-{version}.exe")
        } else {
            format!("saorsa-node-{version}")
        };
        self.cache_dir.join(name)
    }

    /// Return the cached binary path if it exists and its SHA-256 matches
    /// the stored metadata.  Returns `None` on any mismatch or error.
    #[must_use]
    pub fn get_verified(&self, version: &str) -> Option<PathBuf> {
        let bin_path = self.cached_binary_path(version);
        let meta_path = self.meta_path(version);

        let meta_data = fs::read_to_string(&meta_path).ok()?;
        let meta: CachedBinaryMeta = serde_json::from_str(&meta_data).ok()?;

        if meta.version != version {
            debug!("Binary cache version mismatch in metadata");
            return None;
        }

        let actual_hash = sha256_file(&bin_path).ok()?;
        if actual_hash != meta.sha256 {
            warn!(
                "Binary cache SHA-256 mismatch for version {version} (expected {}, got {})",
                meta.sha256, actual_hash
            );
            return None;
        }

        Some(bin_path)
    }

    /// Store a binary in the cache.
    ///
    /// Computes the SHA-256 digest, copies the binary, and writes a
    /// `.meta.json` sidecar file.
    ///
    /// # Errors
    ///
    /// Returns an error if the binary cannot be read or the cache files
    /// cannot be written.
    pub fn store(&self, version: &str, source_path: &std::path::Path) -> Result<()> {
        let hash = sha256_file(source_path)?;

        let dest = self.cached_binary_path(version);
        fs::copy(source_path, &dest)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| Error::Upgrade(format!("System clock error: {e}")))?
            .as_secs();

        let meta = CachedBinaryMeta {
            version: version.to_string(),
            sha256: hash,
            cached_at_epoch_secs: now,
        };

        let meta_json = serde_json::to_string(&meta)
            .map_err(|e| Error::Upgrade(format!("Failed to serialize binary cache meta: {e}")))?;

        let meta_path = self.meta_path(version);
        let mut f = File::create(&meta_path)?;
        f.write_all(meta_json.as_bytes())?;
        f.sync_all()?;

        debug!("Cached binary for version {version} at {}", dest.display());
        Ok(())
    }

    /// Execute `f` while holding an exclusive download lock.
    ///
    /// This prevents multiple nodes from downloading the same archive
    /// concurrently — the first acquires the lock and downloads, the rest
    /// wait and then find the binary already cached.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock cannot be acquired or `f` fails.
    pub fn with_download_lock<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        let lock_path = self.cache_dir.join("download.lock");
        let lock = File::create(&lock_path)
            .map_err(|e| Error::Upgrade(format!("Failed to create download lock: {e}")))?;
        lock.lock_exclusive()
            .map_err(|e| Error::Upgrade(format!("Failed to acquire download lock: {e}")))?;

        let result = f();

        drop(lock); // Dropping the file releases the exclusive lock
        result
    }

    // -- private helpers -----------------------------------------------------

    fn meta_path(&self, version: &str) -> PathBuf {
        let name = if cfg!(windows) {
            format!("saorsa-node-{version}.exe.meta.json")
        } else {
            format!("saorsa-node-{version}.meta.json")
        };
        self.cache_dir.join(name)
    }
}

/// Compute the hex-encoded SHA-256 digest of a file.
fn sha256_file(path: &std::path::Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| Error::Upgrade(format!("Failed to read file for hashing: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_miss_returns_none() {
        let tmp = TempDir::new().unwrap();
        let cache = BinaryCache::new(tmp.path().to_path_buf());
        assert!(cache.get_verified("1.0.0").is_none());
    }

    #[test]
    fn test_store_and_get_verified() {
        let tmp = TempDir::new().unwrap();
        let cache = BinaryCache::new(tmp.path().to_path_buf());

        // Create a fake binary
        let src = tmp.path().join("source-bin");
        fs::write(&src, b"hello world binary").unwrap();

        cache.store("1.2.3", &src).unwrap();

        let result = cache.get_verified("1.2.3");
        assert!(result.is_some());
        let cached_path = result.unwrap();
        assert_eq!(fs::read(&cached_path).unwrap(), b"hello world binary");
    }

    #[test]
    fn test_sha256_mismatch_returns_none() {
        let tmp = TempDir::new().unwrap();
        let cache = BinaryCache::new(tmp.path().to_path_buf());

        // Store a valid binary
        let src = tmp.path().join("source-bin");
        fs::write(&src, b"original content").unwrap();
        cache.store("1.0.0", &src).unwrap();

        // Corrupt the cached binary
        let cached = cache.cached_binary_path("1.0.0");
        fs::write(&cached, b"corrupted content").unwrap();

        assert!(cache.get_verified("1.0.0").is_none());
    }

    #[test]
    fn test_missing_meta_returns_none() {
        let tmp = TempDir::new().unwrap();
        let cache = BinaryCache::new(tmp.path().to_path_buf());

        // Write a binary but no meta file
        let cached = cache.cached_binary_path("1.0.0");
        fs::write(&cached, b"binary data").unwrap();

        assert!(cache.get_verified("1.0.0").is_none());
    }
}
