//! Fetch queue and worker logic (Section 12).
//!
//! Manages a priority queue of keys awaiting record fetch, sorted by
//! XOR distance (nearest-first). Handles concurrency limits, retry
//! with alternate sources, and terminal failure detection.

use crate::client::{xor_distance, XorName};
use crate::replication::params::MAX_PARALLEL_FETCH_BOOTSTRAP;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Fetch entry
// ---------------------------------------------------------------------------

/// A single entry in the fetch queue.
#[derive(Debug, Clone)]
pub struct FetchEntry {
    /// Record key to fetch.
    pub key: XorName,
    /// Verified source peers (peers that responded `Present` during verification).
    pub sources: Vec<String>,
    /// Peers already tried for this fetch (exhausted or failed).
    pub tried: Vec<String>,
}

impl FetchEntry {
    /// Create a new fetch entry.
    #[must_use]
    pub fn new(key: XorName, sources: Vec<String>) -> Self {
        Self {
            key,
            sources,
            tried: Vec::new(),
        }
    }

    /// Get the next untried source peer, if any.
    #[must_use]
    pub fn next_source(&self) -> Option<&str> {
        self.sources
            .iter()
            .find(|s| !self.tried.contains(s))
            .map(String::as_str)
    }

    /// Mark a source as tried.
    pub fn mark_tried(&mut self, peer_id: &str) {
        if !self.tried.iter().any(|p| p == peer_id) {
            self.tried.push(peer_id.to_string());
        }
    }

    /// Whether any untried source remains.
    #[must_use]
    pub fn has_untried_sources(&self) -> bool {
        self.next_source().is_some()
    }
}

// ---------------------------------------------------------------------------
// Fetch queue
// ---------------------------------------------------------------------------

/// Priority queue for record fetches, sorted by XOR distance to self.
///
/// Keys closer to `self_xor` are dequeued first (nearest-first scheduling).
#[derive(Debug)]
pub struct FetchQueue {
    /// Pending fetch entries, keyed by record address.
    entries: HashMap<XorName, FetchEntry>,
    /// Our own XOR name (for distance-based priority).
    self_xor: XorName,
    /// Whether bootstrap mode is active (higher concurrency limit).
    bootstrap_mode: bool,
}

impl FetchQueue {
    /// Create a new empty fetch queue.
    #[must_use]
    pub fn new(self_xor: XorName, bootstrap_mode: bool) -> Self {
        Self {
            entries: HashMap::new(),
            self_xor,
            bootstrap_mode,
        }
    }

    /// Enqueue a key for fetching with verified sources.
    ///
    /// If the key is already queued, the sources are merged (deduped).
    pub fn enqueue(&mut self, key: XorName, sources: Vec<String>) {
        if let Some(entry) = self.entries.get_mut(&key) {
            // Merge sources, deduplicating
            for source in sources {
                if !entry.sources.contains(&source) {
                    entry.sources.push(source);
                }
            }
        } else {
            self.entries.insert(key, FetchEntry::new(key, sources));
        }
    }

    /// Dequeue the next key to fetch (nearest-first).
    ///
    /// Returns `None` if the queue is empty.
    pub fn dequeue(&mut self) -> Option<FetchEntry> {
        if self.entries.is_empty() {
            return None;
        }

        // Find the entry closest to self
        let closest_key = self
            .entries
            .keys()
            .min_by(|a, b| {
                let dist_a = xor_distance(&self.self_xor, a);
                let dist_b = xor_distance(&self.self_xor, b);
                dist_a.cmp(&dist_b)
            })
            .copied();

        closest_key.and_then(|key| self.entries.remove(&key))
    }

    /// Re-enqueue an entry after a retryable failure.
    ///
    /// Preserves the tried set so the same source won't be retried.
    pub fn requeue(&mut self, entry: FetchEntry) {
        self.entries.insert(entry.key, entry);
    }

    /// Remove a key from the queue (e.g., after successful store).
    pub fn remove(&mut self, key: &XorName) {
        self.entries.remove(key);
    }

    /// Check if a key is already queued.
    #[must_use]
    pub fn contains(&self, key: &XorName) -> bool {
        self.entries.contains_key(key)
    }

    /// Number of entries in the queue.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Maximum concurrent fetch operations allowed.
    #[must_use]
    pub fn max_concurrent(&self) -> usize {
        if self.bootstrap_mode {
            MAX_PARALLEL_FETCH_BOOTSTRAP
        } else {
            // Adaptive concurrency outside bootstrap (capped at half bootstrap limit)
            MAX_PARALLEL_FETCH_BOOTSTRAP / 2
        }
    }

    /// Set bootstrap mode on or off.
    pub fn set_bootstrap_mode(&mut self, enabled: bool) {
        self.bootstrap_mode = enabled;
    }

    /// Whether bootstrap mode is active.
    #[must_use]
    pub fn is_bootstrap_mode(&self) -> bool {
        self.bootstrap_mode
    }
}

// ---------------------------------------------------------------------------
// Fetch result types
// ---------------------------------------------------------------------------

/// Outcome of a single fetch attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchAttemptResult {
    /// Record retrieved and content-address verified.
    Success {
        /// Record key.
        key: XorName,
        /// Record content bytes.
        content: Vec<u8>,
    },
    /// Fetch failed but can be retried with an alternate source.
    Retryable {
        /// Record key.
        key: XorName,
        /// Peer that failed.
        failed_source: String,
    },
    /// Fetch abandoned (terminal failure or all sources exhausted).
    Abandoned {
        /// Record key.
        key: XorName,
        /// All peers that were tried.
        tried_sources: Vec<String>,
    },
}

/// Validate a fetched record's content address.
///
/// Returns `true` if `SHA256(content) == key`.
#[must_use]
pub fn validate_content_address(key: &XorName, content: &[u8]) -> bool {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(content);
    let computed: XorName = hash.into();
    computed == *key
}

/// Process a fetch response and determine the next action.
///
/// Returns the appropriate `FetchAttemptResult` based on the response
/// and the entry's remaining sources.
#[must_use]
pub fn process_fetch_response(
    entry: &mut FetchEntry,
    source: &str,
    content: Option<Vec<u8>>,
    is_terminal_failure: bool,
) -> FetchAttemptResult {
    entry.mark_tried(source);

    match content {
        Some(data) if validate_content_address(&entry.key, &data) => FetchAttemptResult::Success {
            key: entry.key,
            content: data,
        },
        Some(_) => {
            // Content-address mismatch — treat as terminal for this source
            if entry.has_untried_sources() {
                FetchAttemptResult::Retryable {
                    key: entry.key,
                    failed_source: source.to_string(),
                }
            } else {
                FetchAttemptResult::Abandoned {
                    key: entry.key,
                    tried_sources: entry.tried.clone(),
                }
            }
        }
        None => {
            if is_terminal_failure || !entry.has_untried_sources() {
                FetchAttemptResult::Abandoned {
                    key: entry.key,
                    tried_sources: entry.tried.clone(),
                }
            } else {
                FetchAttemptResult::Retryable {
                    key: entry.key,
                    failed_source: source.to_string(),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn make_key(byte: u8) -> XorName {
        [byte; 32]
    }

    #[test]
    fn test_fetch_entry_source_tracking() {
        let mut entry =
            FetchEntry::new(make_key(0xAA), vec!["p1".into(), "p2".into(), "p3".into()]);

        assert_eq!(entry.next_source(), Some("p1"));
        assert!(entry.has_untried_sources());

        entry.mark_tried("p1");
        assert_eq!(entry.next_source(), Some("p2"));

        entry.mark_tried("p2");
        assert_eq!(entry.next_source(), Some("p3"));

        entry.mark_tried("p3");
        assert!(entry.next_source().is_none());
        assert!(!entry.has_untried_sources());
    }

    #[test]
    fn test_fetch_entry_mark_tried_idempotent() {
        let mut entry = FetchEntry::new(make_key(0xAA), vec!["p1".into()]);
        entry.mark_tried("p1");
        entry.mark_tried("p1");
        assert_eq!(entry.tried.len(), 1);
    }

    #[test]
    fn test_fetch_queue_enqueue_dequeue() {
        let self_xor = [0xFF; 32]; // far from 0x00, 0x01, etc.
        let mut queue = FetchQueue::new(self_xor, false);

        // Enqueue two keys at different distances
        queue.enqueue(make_key(0x01), vec!["p1".into()]);
        queue.enqueue(make_key(0x02), vec!["p2".into()]);

        assert_eq!(queue.len(), 2);
        assert!(!queue.is_empty());

        // Nearest to 0xFF is the one with XOR distance smallest
        // 0xFF ^ 0x01 = 0xFE, 0xFF ^ 0x02 = 0xFD → 0x02 is closer
        let first = queue.dequeue().unwrap();
        assert_eq!(first.key, make_key(0x02));

        let second = queue.dequeue().unwrap();
        assert_eq!(second.key, make_key(0x01));

        assert!(queue.dequeue().is_none());
        assert!(queue.is_empty());
    }

    #[test]
    fn test_fetch_queue_merge_sources() {
        let mut queue = FetchQueue::new([0x00; 32], false);

        queue.enqueue(make_key(0xAA), vec!["p1".into(), "p2".into()]);
        queue.enqueue(make_key(0xAA), vec!["p2".into(), "p3".into()]);

        assert_eq!(queue.len(), 1);

        let entry = queue.dequeue().unwrap();
        // p2 should not be duplicated
        assert_eq!(entry.sources.len(), 3);
        assert!(entry.sources.contains(&"p1".to_string()));
        assert!(entry.sources.contains(&"p2".to_string()));
        assert!(entry.sources.contains(&"p3".to_string()));
    }

    #[test]
    fn test_fetch_queue_remove() {
        let mut queue = FetchQueue::new([0x00; 32], false);
        queue.enqueue(make_key(0xAA), vec!["p1".into()]);

        assert!(queue.contains(&make_key(0xAA)));
        queue.remove(&make_key(0xAA));
        assert!(!queue.contains(&make_key(0xAA)));
        assert!(queue.is_empty());
    }

    #[test]
    fn test_fetch_queue_requeue() {
        let mut queue = FetchQueue::new([0x00; 32], false);
        let mut entry = FetchEntry::new(make_key(0xAA), vec!["p1".into(), "p2".into()]);
        entry.mark_tried("p1");

        queue.requeue(entry);

        let requeued = queue.dequeue().unwrap();
        assert_eq!(requeued.tried, vec!["p1".to_string()]);
        assert_eq!(requeued.next_source(), Some("p2"));
    }

    #[test]
    fn test_fetch_queue_concurrency_limits() {
        let queue = FetchQueue::new([0x00; 32], true);
        assert_eq!(queue.max_concurrent(), MAX_PARALLEL_FETCH_BOOTSTRAP);

        let queue = FetchQueue::new([0x00; 32], false);
        assert_eq!(queue.max_concurrent(), MAX_PARALLEL_FETCH_BOOTSTRAP / 2);
    }

    #[test]
    fn test_fetch_queue_bootstrap_toggle() {
        let mut queue = FetchQueue::new([0x00; 32], false);
        assert!(!queue.is_bootstrap_mode());

        queue.set_bootstrap_mode(true);
        assert!(queue.is_bootstrap_mode());
        assert_eq!(queue.max_concurrent(), MAX_PARALLEL_FETCH_BOOTSTRAP);
    }

    #[test]
    fn test_validate_content_address() {
        use sha2::{Digest, Sha256};
        let content = b"hello world";
        let hash = Sha256::digest(content);
        let key: XorName = hash.into();

        assert!(validate_content_address(&key, content));
        assert!(!validate_content_address(&key, b"wrong content"));
        assert!(!validate_content_address(&[0x00; 32], content));
    }

    #[test]
    fn test_process_fetch_success() {
        use sha2::{Digest, Sha256};
        let content = b"test data".to_vec();
        let hash = Sha256::digest(&content);
        let key: XorName = hash.into();

        let mut entry = FetchEntry::new(key, vec!["p1".into()]);
        let result = process_fetch_response(&mut entry, "p1", Some(content.clone()), false);

        assert_eq!(result, FetchAttemptResult::Success { key, content });
    }

    #[test]
    fn test_process_fetch_content_mismatch_retryable() {
        let key = make_key(0xAA);
        let mut entry = FetchEntry::new(key, vec!["p1".into(), "p2".into()]);
        let result = process_fetch_response(&mut entry, "p1", Some(b"wrong".to_vec()), false);

        assert_eq!(
            result,
            FetchAttemptResult::Retryable {
                key,
                failed_source: "p1".to_string(),
            }
        );
    }

    #[test]
    fn test_process_fetch_content_mismatch_abandoned() {
        let key = make_key(0xAA);
        let mut entry = FetchEntry::new(key, vec!["p1".into()]);
        let result = process_fetch_response(&mut entry, "p1", Some(b"wrong".to_vec()), false);

        assert_eq!(
            result,
            FetchAttemptResult::Abandoned {
                key,
                tried_sources: vec!["p1".to_string()],
            }
        );
    }

    #[test]
    fn test_process_fetch_not_found_retryable() {
        let key = make_key(0xAA);
        let mut entry = FetchEntry::new(key, vec!["p1".into(), "p2".into()]);
        let result = process_fetch_response(&mut entry, "p1", None, false);

        assert_eq!(
            result,
            FetchAttemptResult::Retryable {
                key,
                failed_source: "p1".to_string(),
            }
        );
    }

    #[test]
    fn test_process_fetch_terminal_failure() {
        let key = make_key(0xAA);
        let mut entry = FetchEntry::new(key, vec!["p1".into(), "p2".into()]);
        let result = process_fetch_response(&mut entry, "p1", None, true);

        assert_eq!(
            result,
            FetchAttemptResult::Abandoned {
                key,
                tried_sources: vec!["p1".to_string()],
            }
        );
    }

    #[test]
    fn test_process_fetch_all_sources_exhausted() {
        let key = make_key(0xAA);
        let mut entry = FetchEntry::new(key, vec!["p1".into()]);
        let result = process_fetch_response(&mut entry, "p1", None, false);

        assert_eq!(
            result,
            FetchAttemptResult::Abandoned {
                key,
                tried_sources: vec!["p1".to_string()],
            }
        );
    }
}
