//! Storage audit challenge-response protocol (Section 15).
//!
//! Implements anti-outsourcing proofs: a challenger selects local keys,
//! discovers which peers should hold them, challenges a randomly-selected
//! peer with a nonce, and verifies per-key digests.
//!
//! All functions are pure logic (no networking). The caller is responsible
//! for performing network lookups and sending/receiving messages.

use crate::client::XorName;
use crate::replication::params::{
    AUDIT_BATCH_SIZE, AUDIT_TICK_INTERVAL_MAX_SECS, AUDIT_TICK_INTERVAL_MIN_SECS,
    BOOTSTRAP_CLAIM_GRACE_PERIOD_SECS,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;
use std::time::{Duration, Instant};

/// Sentinel digest indicating the target does not hold a challenged key.
///
/// A malicious target could return this sentinel to be classified as `Absent`
/// instead of `Failed`. However, `failed_keys` treats both identically for
/// trust-penalty purposes, so this does not create an exploitable advantage.
/// Callers MUST treat `Absent` and `Failed` equivalently.
pub const ABSENT_DIGEST: [u8; 32] = [0u8; 32];

// ---------------------------------------------------------------------------
// Audit key sampling (Section 15, step 2)
// ---------------------------------------------------------------------------

/// Sample up to `AUDIT_BATCH_SIZE` keys uniformly from the local store.
///
/// Uses a simple modular selection seeded by `rng_seed` for deterministic
/// testing. Returns an empty vec if `local_keys` is empty.
#[must_use]
pub fn sample_audit_keys(local_keys: &[XorName], rng_seed: u64) -> Vec<XorName> {
    if local_keys.is_empty() {
        return Vec::new();
    }

    let count = local_keys.len().min(AUDIT_BATCH_SIZE);

    if count >= local_keys.len() {
        // Fewer keys than batch size — take all
        return local_keys.to_vec();
    }

    // Simple deterministic sampling: hash the seed to get starting offset,
    // then stride through the array
    #[allow(clippy::cast_possible_truncation)]
    let start = (rng_seed as usize) % local_keys.len();
    let stride = if local_keys.len() > count {
        local_keys.len() / count
    } else {
        1
    };

    let mut sampled = Vec::with_capacity(count);
    let mut idx = start;
    for _ in 0..count {
        sampled.push(local_keys[idx % local_keys.len()]);
        idx += stride;
    }

    sampled
}

// ---------------------------------------------------------------------------
// Candidate peer construction (Section 15, steps 4-6)
// ---------------------------------------------------------------------------

/// Per-peer key set built from network lookup results.
#[derive(Debug, Clone)]
pub struct PeerKeySet {
    /// The peer's ID.
    pub peer_id: String,
    /// Subset of seed keys whose lookup result included this peer.
    pub keys: Vec<XorName>,
}

/// Build candidate peer sets from lookup results.
///
/// `lookup_results` maps each seed key to the set of peer IDs returned
/// by the closest-peer network lookup for that key.
///
/// `local_rt_ids` is the set of peer IDs in the challenger's `LocalRT`.
///
/// Returns only peers with non-empty key sets, filtered to `LocalRT`.
#[must_use]
pub fn build_candidate_peer_sets<S: BuildHasher>(
    lookup_results: &[(XorName, Vec<String>)],
    local_rt_ids: &HashSet<String, S>,
) -> Vec<PeerKeySet> {
    let mut peer_keys: HashMap<String, Vec<XorName>> = HashMap::new();

    for (key, peers) in lookup_results {
        for peer_id in peers {
            if local_rt_ids.contains(peer_id) {
                peer_keys.entry(peer_id.clone()).or_default().push(*key);
            }
        }
    }

    peer_keys
        .into_iter()
        .filter(|(_, keys)| !keys.is_empty())
        .map(|(peer_id, keys)| PeerKeySet { peer_id, keys })
        .collect()
}

/// Select a challenged peer from candidates using a seed.
///
/// Returns `None` if candidates is empty.
#[must_use]
pub fn select_challenged_peer(candidates: &[PeerKeySet], rng_seed: u64) -> Option<&PeerKeySet> {
    if candidates.is_empty() {
        return None;
    }
    #[allow(clippy::cast_possible_truncation)]
    let idx = (rng_seed as usize) % candidates.len();
    Some(&candidates[idx])
}

// ---------------------------------------------------------------------------
// Digest computation (Section 15, step 9a / 10)
// ---------------------------------------------------------------------------

/// Compute `AuditKeyDigest(K_i) = H(nonce || challenged_peer_id || K_i || record_bytes_i)`.
#[must_use]
pub fn compute_audit_digest(
    nonce: &[u8; 32],
    peer_id: &str,
    key: &XorName,
    record_bytes: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(nonce);
    hasher.update(peer_id.as_bytes());
    hasher.update(key);
    hasher.update(record_bytes);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Response verification (Section 15, step 10)
// ---------------------------------------------------------------------------

/// Result of verifying a single key in an audit response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditKeyResult {
    /// Digest matches — key is held correctly.
    Passed,
    /// Digest mismatch — key may not be held correctly.
    Failed,
    /// Target signalled absence for this key position.
    Absent,
}

/// Verify an audit response against local records.
///
/// `challenge_keys` and `response_digests` must have the same length.
/// `local_records` provides the raw bytes for each challenged key.
///
/// Returns per-key results in challenge order. If response length
/// doesn't match challenge length, returns `None` (malformed response).
#[must_use]
pub fn verify_audit_response<S: BuildHasher>(
    nonce: &[u8; 32],
    peer_id: &str,
    challenge_keys: &[XorName],
    response_digests: &[[u8; 32]],
    local_records: &HashMap<XorName, Vec<u8>, S>,
) -> Option<Vec<AuditKeyResult>> {
    if challenge_keys.len() != response_digests.len() {
        return None; // Malformed: wrong number of digests
    }

    let results = challenge_keys
        .iter()
        .zip(response_digests.iter())
        .map(|(key, response_digest)| {
            if *response_digest == ABSENT_DIGEST {
                return AuditKeyResult::Absent;
            }

            // Recompute expected digest from local copy
            let Some(record_bytes) = local_records.get(key) else {
                // We don't have local copy — can't verify (treat as failed)
                return AuditKeyResult::Failed;
            };

            let expected = compute_audit_digest(nonce, peer_id, key, record_bytes);
            if expected == *response_digest {
                AuditKeyResult::Passed
            } else {
                AuditKeyResult::Failed
            }
        })
        .collect();

    Some(results)
}

/// Collect the keys that failed verification.
#[must_use]
pub fn failed_keys(challenge_keys: &[XorName], results: &[AuditKeyResult]) -> Vec<XorName> {
    challenge_keys
        .iter()
        .zip(results.iter())
        .filter(|(_, result)| matches!(result, AuditKeyResult::Failed | AuditKeyResult::Absent))
        .map(|(key, _)| *key)
        .collect()
}

// ---------------------------------------------------------------------------
// Responsibility confirmation (Section 15, step 11)
// ---------------------------------------------------------------------------

/// Filter failed keys by responsibility confirmation.
///
/// `fresh_lookup_results` maps each failed key to the set of peer IDs
/// from a fresh closest-peer lookup. Keys where `challenged_peer_id`
/// does NOT appear in the fresh lookup are removed from the failure set.
#[must_use]
pub fn confirm_failures<S: BuildHasher>(
    failed: &[XorName],
    challenged_peer_id: &str,
    fresh_lookup_results: &HashMap<XorName, Vec<String>, S>,
) -> Vec<XorName> {
    failed
        .iter()
        .filter(|key| {
            fresh_lookup_results
                .get(*key)
                .is_some_and(|peers| peers.iter().any(|p| p == challenged_peer_id))
        })
        .copied()
        .collect()
}

// ---------------------------------------------------------------------------
// Bootstrap claim handling (Section 15, step 9b)
// ---------------------------------------------------------------------------

/// Outcome of processing a bootstrap claim during an audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapClaimOutcome {
    /// Claim accepted within grace period.
    Accepted,
    /// Claim is past grace period — abuse evidence should be emitted.
    Abuse,
}

/// Process a bootstrap claim from an audit target.
#[must_use]
pub fn process_bootstrap_claim(first_seen: Instant) -> BootstrapClaimOutcome {
    let grace = Duration::from_secs(BOOTSTRAP_CLAIM_GRACE_PERIOD_SECS);
    if first_seen.elapsed() < grace {
        BootstrapClaimOutcome::Accepted
    } else {
        BootstrapClaimOutcome::Abuse
    }
}

// ---------------------------------------------------------------------------
// Audit tick scheduling
// ---------------------------------------------------------------------------

/// Compute a randomized audit tick interval within the configured range.
#[must_use]
pub fn jittered_audit_interval(rng_u64: u64) -> Duration {
    let range = AUDIT_TICK_INTERVAL_MAX_SECS - AUDIT_TICK_INTERVAL_MIN_SECS;
    let jitter = if range == 0 { 0 } else { rng_u64 % (range + 1) };
    Duration::from_secs(AUDIT_TICK_INTERVAL_MIN_SECS + jitter)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_sample_audit_keys_empty() {
        let result = sample_audit_keys(&[], 42);
        assert!(result.is_empty());
    }

    #[test]
    fn test_sample_audit_keys_fewer_than_batch() {
        let keys: Vec<XorName> = (0..3).map(|i| [i; 32]).collect();
        let result = sample_audit_keys(&keys, 0);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_sample_audit_keys_capped_at_batch_size() {
        let keys: Vec<XorName> = (0..50).map(|i| [i; 32]).collect();
        let result = sample_audit_keys(&keys, 123);
        assert_eq!(result.len(), AUDIT_BATCH_SIZE);
    }

    #[test]
    fn test_sample_audit_keys_deterministic() {
        let keys: Vec<XorName> = (0..20).map(|i| [i; 32]).collect();
        let r1 = sample_audit_keys(&keys, 42);
        let r2 = sample_audit_keys(&keys, 42);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_build_candidate_peer_sets() {
        let mut local_rt = HashSet::new();
        local_rt.insert("peer_a".to_string());
        local_rt.insert("peer_b".to_string());
        // peer_c is NOT in local_rt

        let key1 = [0x01; 32];
        let key2 = [0x02; 32];

        let lookups = vec![
            (key1, vec!["peer_a".to_string(), "peer_c".to_string()]),
            (key2, vec!["peer_a".to_string(), "peer_b".to_string()]),
        ];

        let candidates = build_candidate_peer_sets(&lookups, &local_rt);

        // peer_a should have both keys, peer_b has key2, peer_c filtered out
        let peer_a = candidates.iter().find(|c| c.peer_id == "peer_a");
        assert!(peer_a.is_some());
        assert_eq!(peer_a.unwrap().keys.len(), 2);

        let peer_b = candidates.iter().find(|c| c.peer_id == "peer_b");
        assert!(peer_b.is_some());
        assert_eq!(peer_b.unwrap().keys.len(), 1);

        let peer_c = candidates.iter().find(|c| c.peer_id == "peer_c");
        assert!(peer_c.is_none());
    }

    #[test]
    fn test_build_candidate_peer_sets_empty_after_filter() {
        let local_rt = HashSet::new(); // empty — no peers in RT
        let lookups = vec![([0x01; 32], vec!["peer_a".to_string()])];

        let candidates = build_candidate_peer_sets(&lookups, &local_rt);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_select_challenged_peer_empty() {
        let candidates: Vec<PeerKeySet> = vec![];
        assert!(select_challenged_peer(&candidates, 0).is_none());
    }

    #[test]
    fn test_select_challenged_peer_deterministic() {
        let candidates = vec![
            PeerKeySet {
                peer_id: "peer_a".to_string(),
                keys: vec![[0x01; 32]],
            },
            PeerKeySet {
                peer_id: "peer_b".to_string(),
                keys: vec![[0x02; 32]],
            },
        ];

        let p1 = select_challenged_peer(&candidates, 42).unwrap();
        let p2 = select_challenged_peer(&candidates, 42).unwrap();
        assert_eq!(p1.peer_id, p2.peer_id);
    }

    #[test]
    fn test_compute_audit_digest_deterministic() {
        let nonce = [0xAA; 32];
        let peer_id = "target_peer";
        let key = [0xBB; 32];
        let record = b"some record data";

        let d1 = compute_audit_digest(&nonce, peer_id, &key, record);
        let d2 = compute_audit_digest(&nonce, peer_id, &key, record);
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_compute_audit_digest_differs_with_nonce() {
        let nonce1 = [0xAA; 32];
        let nonce2 = [0xBB; 32];
        let peer_id = "peer";
        let key = [0x01; 32];
        let record = b"data";

        let d1 = compute_audit_digest(&nonce1, peer_id, &key, record);
        let d2 = compute_audit_digest(&nonce2, peer_id, &key, record);
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_compute_audit_digest_differs_with_key() {
        let nonce = [0xAA; 32];
        let peer_id = "peer";
        let key1 = [0x01; 32];
        let key2 = [0x02; 32];
        let record = b"data";

        let d1 = compute_audit_digest(&nonce, peer_id, &key1, record);
        let d2 = compute_audit_digest(&nonce, peer_id, &key2, record);
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_verify_audit_response_all_pass() {
        let nonce = [0x42; 32];
        let peer_id = "target";
        let key1 = [0x01; 32];
        let key2 = [0x02; 32];
        let record1 = b"record one".to_vec();
        let record2 = b"record two".to_vec();

        let d1 = compute_audit_digest(&nonce, peer_id, &key1, &record1);
        let d2 = compute_audit_digest(&nonce, peer_id, &key2, &record2);

        let mut local = HashMap::new();
        local.insert(key1, record1);
        local.insert(key2, record2);

        let results = verify_audit_response(&nonce, peer_id, &[key1, key2], &[d1, d2], &local);
        let results = results.unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| *r == AuditKeyResult::Passed));
    }

    #[test]
    fn test_verify_audit_response_mismatch() {
        let nonce = [0x42; 32];
        let peer_id = "target";
        let key = [0x01; 32];
        let record = b"correct data".to_vec();
        let bad_digest = [0xFF; 32]; // wrong digest

        let mut local = HashMap::new();
        local.insert(key, record);

        let results = verify_audit_response(&nonce, peer_id, &[key], &[bad_digest], &local);
        let results = results.unwrap();
        assert_eq!(results[0], AuditKeyResult::Failed);
    }

    #[test]
    fn test_verify_audit_response_absent() {
        let nonce = [0x42; 32];
        let peer_id = "target";
        let key = [0x01; 32];
        let record = b"data".to_vec();

        let mut local = HashMap::new();
        local.insert(key, record);

        let results = verify_audit_response(&nonce, peer_id, &[key], &[ABSENT_DIGEST], &local);
        let results = results.unwrap();
        assert_eq!(results[0], AuditKeyResult::Absent);
    }

    #[test]
    fn test_verify_audit_response_wrong_length() {
        let nonce = [0x42; 32];
        let peer_id = "target";
        let keys = vec![[0x01; 32], [0x02; 32]];
        let digests = vec![[0xAA; 32]]; // Only 1 digest for 2 keys
        let local = HashMap::new();

        let result = verify_audit_response(&nonce, peer_id, &keys, &digests, &local);
        assert!(result.is_none()); // Malformed
    }

    #[test]
    fn test_failed_keys_collection() {
        let keys = vec![[0x01; 32], [0x02; 32], [0x03; 32]];
        let results = vec![
            AuditKeyResult::Passed,
            AuditKeyResult::Failed,
            AuditKeyResult::Absent,
        ];

        let failures = failed_keys(&keys, &results);
        assert_eq!(failures.len(), 2);
        assert!(failures.contains(&[0x02; 32]));
        assert!(failures.contains(&[0x03; 32]));
    }

    #[test]
    fn test_confirm_failures_filters_non_responsible() {
        let failed = vec![[0x01; 32], [0x02; 32]];
        let challenged_peer = "peer_a";

        let mut fresh_lookups = HashMap::new();
        // peer_a appears in fresh lookup for key 0x01 but not 0x02
        fresh_lookups.insert([0x01; 32], vec!["peer_a".to_string(), "peer_b".to_string()]);
        fresh_lookups.insert([0x02; 32], vec!["peer_c".to_string()]);

        let confirmed = confirm_failures(&failed, challenged_peer, &fresh_lookups);
        assert_eq!(confirmed.len(), 1);
        assert_eq!(confirmed[0], [0x01; 32]);
    }

    #[test]
    fn test_confirm_failures_all_cleared() {
        let failed = vec![[0x01; 32]];
        let mut fresh_lookups = HashMap::new();
        fresh_lookups.insert([0x01; 32], vec!["peer_x".to_string()]);

        let confirmed = confirm_failures(&failed, "peer_a", &fresh_lookups);
        assert!(confirmed.is_empty());
    }

    #[test]
    fn test_jittered_audit_interval_bounds() {
        for seed in 0..100 {
            let interval = jittered_audit_interval(seed);
            assert!(interval >= Duration::from_secs(AUDIT_TICK_INTERVAL_MIN_SECS));
            assert!(interval <= Duration::from_secs(AUDIT_TICK_INTERVAL_MAX_SECS));
        }
    }
}
