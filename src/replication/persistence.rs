//! Shared persistence helpers for replication state.
//!
//! Uses atomic write (temp file + rename) following the `DiskStorage` pattern.

use crate::error::{Error, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::Path;
use tracing::{debug, warn};

/// Atomically write serialized data to `path` via temp file + rename.
///
/// # Errors
///
/// Returns an error if serialization, file creation, or rename fails.
pub fn atomic_write<T: Serialize>(path: &Path, data: &T) -> Result<()> {
    let bytes = postcard::to_allocvec(data)
        .map_err(|e| Error::Replication(format!("serialization failed: {e}")))?;

    let temp_path = path.with_extension("tmp");

    std::fs::write(&temp_path, &bytes)
        .map_err(|e| Error::Replication(format!("failed to write temp file: {e}")))?;

    std::fs::rename(&temp_path, path)
        .map_err(|e| Error::Replication(format!("failed to rename temp file: {e}")))?;

    debug!("Wrote {} bytes to {}", bytes.len(), path.display());

    Ok(())
}

/// Load and deserialize data from `path`, returning `None` if the file
/// is missing or corrupt.
pub fn safe_load<T: DeserializeOwned>(path: &Path) -> Option<T> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!("Failed to read {}: {e}", path.display());
            }
            return None;
        }
    };

    match postcard::from_bytes(&bytes) {
        Ok(data) => Some(data),
        Err(e) => {
            warn!(
                "Failed to deserialize {}: {e} (file may be corrupt)",
                path.display()
            );
            None
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use tempfile::TempDir;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestData {
        value: u64,
        name: String,
    }

    #[test]
    fn test_atomic_write_and_load() {
        let dir = TempDir::new().expect("create temp dir");
        let path = dir.path().join("test.bin");

        let data = TestData {
            value: 42,
            name: "hello".to_string(),
        };

        atomic_write(&path, &data).expect("write");
        let loaded: TestData = safe_load(&path).expect("load");
        assert_eq!(loaded, data);
    }

    #[test]
    fn test_safe_load_missing_file() {
        let dir = TempDir::new().expect("create temp dir");
        let path = dir.path().join("nonexistent.bin");

        let result: Option<TestData> = safe_load(&path);
        assert!(result.is_none());
    }

    #[test]
    fn test_safe_load_corrupt_file() {
        let dir = TempDir::new().expect("create temp dir");
        let path = dir.path().join("corrupt.bin");

        std::fs::write(&path, b"this is not valid postcard").expect("write");

        let result: Option<TestData> = safe_load(&path);
        assert!(result.is_none());
    }

    #[test]
    fn test_atomic_write_overwrites() {
        let dir = TempDir::new().expect("create temp dir");
        let path = dir.path().join("overwrite.bin");

        let data1 = TestData {
            value: 1,
            name: "first".to_string(),
        };
        let data2 = TestData {
            value: 2,
            name: "second".to_string(),
        };

        atomic_write(&path, &data1).expect("write 1");
        atomic_write(&path, &data2).expect("write 2");

        let loaded: TestData = safe_load(&path).expect("load");
        assert_eq!(loaded, data2);
    }
}
