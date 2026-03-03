//! Persistent `PaidForList` (Section 3, 5.15).
//!
//! In-memory `HashSet<XorName>` backed by atomic disk writes.
//! On corrupt file recovery: start empty and rely on Section 7.2 rule 4
//! (close-group replica majority) for re-derivation.

use crate::client::XorName;
use crate::error::{Error, Result};
use crate::replication::persistence;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

/// File name for the persisted paid-for list.
const PAID_LIST_FILENAME: &str = "paid_for_list.bin";

/// Persistent set of keys this node believes are paid-authorized.
///
/// Must survive node restarts (Invariant 15). Uses atomic writes
/// for crash safety.
#[derive(Debug)]
pub struct PaidForList {
    /// In-memory set of paid keys.
    keys: HashSet<XorName>,
    /// Path to the on-disk persistence file.
    path: PathBuf,
    /// Whether the in-memory set has been modified since last flush.
    dirty: bool,
}

/// Serializable representation for disk persistence.
#[derive(Serialize, Deserialize)]
struct PaidForListData {
    keys: Vec<XorName>,
}

impl PaidForList {
    /// Load from disk, or create empty if file is missing or corrupt.
    ///
    /// # Errors
    ///
    /// Returns an error only if the parent directory cannot be created.
    pub fn load(root_dir: &Path) -> Result<Self> {
        let replication_dir = root_dir.join("replication");
        std::fs::create_dir_all(&replication_dir).map_err(|e| {
            Error::Replication(format!("failed to create replication directory: {e}"))
        })?;

        let path = replication_dir.join(PAID_LIST_FILENAME);

        let keys = if let Some(data) = persistence::safe_load::<PaidForListData>(&path) {
            let set: HashSet<XorName> = data.keys.into_iter().collect();
            debug!("Loaded PaidForList with {} keys", set.len());
            set
        } else {
            debug!("PaidForList file missing or corrupt, starting empty");
            HashSet::new()
        };

        Ok(Self {
            keys,
            path,
            dirty: false,
        })
    }

    /// Add a key to the paid-for list.
    ///
    /// Returns `true` if the key was newly added.
    pub fn add(&mut self, key: XorName) -> bool {
        let inserted = self.keys.insert(key);
        if inserted {
            self.dirty = true;
        }
        inserted
    }

    /// Remove a key from the paid-for list.
    ///
    /// Returns `true` if the key was present.
    pub fn remove(&mut self, key: &XorName) -> bool {
        let removed = self.keys.remove(key);
        if removed {
            self.dirty = true;
        }
        removed
    }

    /// Check if a key is in the paid-for list.
    #[must_use]
    pub fn contains(&self, key: &XorName) -> bool {
        self.keys.contains(key)
    }

    /// Get all keys in the paid-for list.
    #[must_use]
    pub fn keys(&self) -> Vec<XorName> {
        self.keys.iter().copied().collect()
    }

    /// Number of keys in the list.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Whether the in-memory state has been modified since last flush.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Flush to disk if dirty. Uses atomic write (temp + rename).
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    pub fn flush(&mut self) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }

        let data = PaidForListData {
            keys: self.keys.iter().copied().collect(),
        };

        persistence::atomic_write(&self.path, &data)?;
        self.dirty = false;
        debug!("Flushed PaidForList ({} keys) to disk", self.keys.len());
        Ok(())
    }
}

impl Drop for PaidForList {
    fn drop(&mut self) {
        if self.dirty {
            if let Err(e) = self.flush() {
                warn!("Failed to flush PaidForList on drop: {e}");
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_dir() -> TempDir {
        TempDir::new().expect("create temp dir")
    }

    #[test]
    fn test_add_contains_remove() {
        let dir = test_dir();
        let mut list = PaidForList::load(dir.path()).expect("load");

        let key = [0xAA; 32];

        assert!(!list.contains(&key));
        assert!(list.add(key));
        assert!(list.contains(&key));
        assert!(!list.add(key)); // duplicate
        assert_eq!(list.len(), 1);

        assert!(list.remove(&key));
        assert!(!list.contains(&key));
        assert!(!list.remove(&key)); // already removed
        assert!(list.is_empty());
    }

    #[test]
    fn test_persistence_roundtrip() {
        let dir = test_dir();
        let key1 = [0x01; 32];
        let key2 = [0x02; 32];

        // Write
        {
            let mut list = PaidForList::load(dir.path()).expect("load");
            list.add(key1);
            list.add(key2);
            list.flush().expect("flush");
        }

        // Read back
        {
            let list = PaidForList::load(dir.path()).expect("reload");
            assert_eq!(list.len(), 2);
            assert!(list.contains(&key1));
            assert!(list.contains(&key2));
        }
    }

    #[test]
    fn test_corrupt_file_starts_empty() {
        let dir = test_dir();
        let replication_dir = dir.path().join("replication");
        std::fs::create_dir_all(&replication_dir).expect("create dir");

        // Write garbage
        std::fs::write(
            replication_dir.join(PAID_LIST_FILENAME),
            b"not valid postcard",
        )
        .expect("write garbage");

        let list = PaidForList::load(dir.path()).expect("load");
        assert!(list.is_empty());
    }

    #[test]
    fn test_dirty_flag() {
        let dir = test_dir();
        let mut list = PaidForList::load(dir.path()).expect("load");

        assert!(!list.is_dirty());

        list.add([0x01; 32]);
        assert!(list.is_dirty());

        list.flush().expect("flush");
        assert!(!list.is_dirty());

        // Remove marks dirty again
        list.remove(&[0x01; 32]);
        assert!(list.is_dirty());
    }

    #[test]
    fn test_keys_returns_all() {
        let dir = test_dir();
        let mut list = PaidForList::load(dir.path()).expect("load");

        let keys: Vec<XorName> = (0..5u8).map(|i| [i; 32]).collect();
        for k in &keys {
            list.add(*k);
        }

        let mut returned = list.keys();
        returned.sort_unstable();
        let mut expected = keys;
        expected.sort_unstable();
        assert_eq!(returned, expected);
    }
}
