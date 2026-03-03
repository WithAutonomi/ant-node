//! Routing helpers for Kademlia-style replication (Section 3, 11).
//!
//! All functions operate on local views and do not perform network lookups.

use crate::client::{xor_distance, XorName};
use crate::replication::params::{CLOSE_GROUP_SIZE, PAID_LIST_CLOSE_GROUP_SIZE, QUORUM_THRESHOLD};

/// Sort peer IDs by XOR distance to `target` (nearest first).
///
/// The returned vector contains `(peer_id, xor_name)` pairs, sorted ascending
/// by distance.
#[must_use]
pub fn sort_by_distance(target: &XorName, peers: &[(String, XorName)]) -> Vec<(String, XorName)> {
    let mut with_distance: Vec<_> = peers
        .iter()
        .map(|(id, name)| {
            let dist = xor_distance(target, name);
            (id.clone(), *name, dist)
        })
        .collect();

    with_distance.sort_by(|a, b| a.2.cmp(&b.2));

    with_distance
        .into_iter()
        .map(|(id, name, _)| (id, name))
        .collect()
}

/// Return the `size` nearest peers to `key` (Section 3: `CloseGroup(K)`).
#[must_use]
pub fn close_group(
    key: &XorName,
    peers: &[(String, XorName)],
    size: usize,
) -> Vec<(String, XorName)> {
    let sorted = sort_by_distance(key, peers);
    sorted.into_iter().take(size).collect()
}

/// Check if `self_id` is among the `CLOSE_GROUP_SIZE` nearest nodes to `key`
/// in `SelfInclusiveRT` (Section 3: `IsResponsible(N, K)`).
///
/// `local_rt` is `LocalRT(N)` — the set of peers excluding `self`.
/// This function internally constructs `SelfInclusiveRT = LocalRT ∪ {self}`.
#[must_use]
pub fn is_responsible(
    self_id: &str,
    self_xor: &XorName,
    key: &XorName,
    local_rt: &[(String, XorName)],
) -> bool {
    is_responsible_with_size(self_id, self_xor, key, local_rt, CLOSE_GROUP_SIZE)
}

/// Same as [`is_responsible`] but with a configurable close group size.
#[must_use]
pub fn is_responsible_with_size(
    self_id: &str,
    self_xor: &XorName,
    key: &XorName,
    local_rt: &[(String, XorName)],
    group_size: usize,
) -> bool {
    // Build SelfInclusiveRT
    let mut self_inclusive: Vec<(String, XorName)> = local_rt.to_vec();
    self_inclusive.push((self_id.to_string(), *self_xor));

    let nearest = close_group(key, &self_inclusive, group_size);
    nearest.iter().any(|(id, _)| id == self_id)
}

/// Return the `PAID_LIST_CLOSE_GROUP_SIZE` nearest nodes to `key`
/// (Section 3: `PaidCloseGroup(K)`).
///
/// Evaluated from `SelfInclusiveRT(querying_node)`.
#[must_use]
pub fn paid_close_group(
    self_id: &str,
    self_xor: &XorName,
    key: &XorName,
    local_rt: &[(String, XorName)],
) -> Vec<(String, XorName)> {
    let mut self_inclusive: Vec<(String, XorName)> = local_rt.to_vec();
    self_inclusive.push((self_id.to_string(), *self_xor));
    close_group(key, &self_inclusive, PAID_LIST_CLOSE_GROUP_SIZE)
}

/// Return the `scope` nearest peers to `self` in `LocalRT(self)`
/// (Section 3: `CloseNeighbors(N)`).
#[must_use]
pub fn close_neighbors(
    self_xor: &XorName,
    local_rt: &[(String, XorName)],
    scope: usize,
) -> Vec<(String, XorName)> {
    close_group(self_xor, local_rt, scope)
}

/// Dynamic quorum threshold for a key (Section 9 step 6).
///
/// `QuorumNeeded(K) = min(QUORUM_THRESHOLD, floor(|QuorumTargets|/2)+1)`
#[must_use]
pub fn quorum_needed(quorum_targets_count: usize) -> usize {
    let dynamic = quorum_targets_count / 2 + 1;
    std::cmp::min(QUORUM_THRESHOLD, dynamic)
}

/// Dynamic quorum threshold with a configurable base threshold.
#[must_use]
pub fn quorum_needed_with_threshold(quorum_targets_count: usize, threshold: usize) -> usize {
    let dynamic = quorum_targets_count / 2 + 1;
    std::cmp::min(threshold, dynamic)
}

/// Dynamic paid-list confirmation count (Section 3).
///
/// `ConfirmNeeded(K) = floor(PaidGroupSize(K)/2)+1`
#[must_use]
pub fn confirm_needed(paid_group_size: usize) -> usize {
    paid_group_size / 2 + 1
}

/// Compute `QuorumTargets` — up to `CLOSE_GROUP_SIZE` nearest known peers
/// for key `K` in `LocalRT(self)` (excluding self) (Section 9 step 3).
#[must_use]
pub fn quorum_targets(key: &XorName, local_rt: &[(String, XorName)]) -> Vec<(String, XorName)> {
    close_group(key, local_rt, CLOSE_GROUP_SIZE)
}

/// Check if self is in `PaidCloseGroup(K)`.
#[must_use]
pub fn is_in_paid_close_group(
    self_id: &str,
    self_xor: &XorName,
    key: &XorName,
    local_rt: &[(String, XorName)],
) -> bool {
    let group = paid_close_group(self_id, self_xor, key, local_rt);
    group.iter().any(|(id, _)| id == self_id)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn make_peers(xors: &[[u8; 32]]) -> Vec<(String, XorName)> {
        xors.iter()
            .enumerate()
            .map(|(i, x)| (format!("peer_{i}"), *x))
            .collect()
    }

    #[test]
    fn test_sort_by_distance() {
        let target = [0x00; 32];
        let mut close = [0x00; 32];
        close[0] = 0x01; // distance = 0x01...
        let mut far = [0x00; 32];
        far[0] = 0xFF; // distance = 0xFF...

        let peers = make_peers(&[far, close]);
        let sorted = sort_by_distance(&target, &peers);

        assert_eq!(sorted[0].1, close);
        assert_eq!(sorted[1].1, far);
    }

    #[test]
    fn test_close_group_size() {
        let target = [0x00; 32];
        let mut peers = Vec::new();
        for i in 0..20u8 {
            let mut xor = [0x00; 32];
            xor[0] = i + 1;
            peers.push((format!("peer_{i}"), xor));
        }

        let group = close_group(&target, &peers, CLOSE_GROUP_SIZE);
        assert_eq!(group.len(), CLOSE_GROUP_SIZE);

        // Verify they are the closest
        for (_, xor) in &group {
            #[allow(clippy::cast_possible_truncation)]
            let close_group_byte: u8 = CLOSE_GROUP_SIZE as u8;
            assert!(xor[0] <= close_group_byte);
        }
    }

    #[test]
    fn test_is_responsible_when_close() {
        let self_xor = [0x01; 32]; // very close to target
        let target = [0x00; 32];

        // Create peers that are farther away
        let peers: Vec<_> = (2..=10u8)
            .map(|i| {
                let mut xor = [0x00; 32];
                xor[0] = i * 0x10;
                (format!("peer_{i}"), xor)
            })
            .collect();

        assert!(is_responsible("self", &self_xor, &target, &peers));
    }

    #[test]
    fn test_is_responsible_when_far() {
        let self_xor = [0xFF; 32]; // very far from target
        let target = [0x00; 32];

        // Create 7+ peers that are closer
        let peers: Vec<_> = (1..=10u8)
            .map(|i| {
                let mut xor = [0x00; 32];
                xor[0] = i;
                (format!("peer_{i}"), xor)
            })
            .collect();

        assert!(!is_responsible("self", &self_xor, &target, &peers));
    }

    #[test]
    fn test_quorum_needed_full_group() {
        // |QuorumTargets| = 7 -> floor(7/2)+1 = 4 -> min(4, 4) = 4
        assert_eq!(quorum_needed(CLOSE_GROUP_SIZE), QUORUM_THRESHOLD);
    }

    #[test]
    fn test_quorum_needed_undersized() {
        // |QuorumTargets| = 3 -> floor(3/2)+1 = 2 -> min(4, 2) = 2
        assert_eq!(quorum_needed(3), 2);
    }

    #[test]
    fn test_quorum_needed_single_peer() {
        // |QuorumTargets| = 1 -> floor(1/2)+1 = 1 -> min(4, 1) = 1
        assert_eq!(quorum_needed(1), 1);
    }

    #[test]
    fn test_confirm_needed() {
        // PaidGroupSize = 20 -> floor(20/2)+1 = 11
        assert_eq!(confirm_needed(20), 11);
        // PaidGroupSize = 8 -> floor(8/2)+1 = 5
        assert_eq!(confirm_needed(8), 5);
        // PaidGroupSize = 1 -> floor(1/2)+1 = 1
        assert_eq!(confirm_needed(1), 1);
    }

    #[test]
    fn test_close_neighbors() {
        let self_xor = [0x80; 32];
        let mut peers = Vec::new();
        for i in 0..30u8 {
            let mut xor = [0x80; 32];
            xor[0] = 0x80 ^ (i + 1); // varying distance from self
            peers.push((format!("peer_{i}"), xor));
        }

        let neighbors = close_neighbors(&self_xor, &peers, 20);
        assert_eq!(neighbors.len(), 20);
    }

    #[test]
    fn test_is_in_paid_close_group() {
        let self_xor = [0x01; 32]; // close to key
        let key = [0x00; 32];

        // Create a few peers
        let peers: Vec<_> = (2..=5u8)
            .map(|i| {
                let mut xor = [0x00; 32];
                xor[0] = i;
                (format!("peer_{i}"), xor)
            })
            .collect();

        // With small network, self should be in paid close group
        assert!(is_in_paid_close_group("self", &self_xor, &key, &peers));
    }
}
