//! Close group confirmation protocol.
//!
//! Provides utilities for verifying close group membership with quorum-based
//! consensus. Multiple nodes independently look up the same address and peers
//! that appear in at least a configurable threshold of those lookups form the
//! "confirmed" close group.
//!
//! This addresses the DHT routing table incompleteness problem where different
//! nodes may return different closest-node sets for the same address.

use saorsa_core::P2PNode;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

use crate::ant_protocol::CLOSE_GROUP_SIZE;
use crate::client::{peer_id_to_xor_name, xor_distance, XorName};

/// Default timeout for a single DHT lookup during confirmation.
const CONFIRMATION_LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);

/// Result of a close group confirmation query.
#[derive(Debug, Clone)]
pub struct ConfirmedCloseGroup {
    /// Peer IDs that appeared in at least `threshold` of the lookups.
    /// Sorted by XOR distance to the target address.
    pub members: Vec<String>,

    /// How many independent lookups were performed.
    pub num_lookups: usize,

    /// How many lookups returned non-empty results.
    pub num_responses: usize,

    /// The confirmation threshold used (minimum appearances required).
    pub threshold: usize,
}

impl ConfirmedCloseGroup {
    /// Check if the confirmed group has at least `CLOSE_GROUP_SIZE` members.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.members.len() >= CLOSE_GROUP_SIZE
    }

    /// Check if a given peer ID (hex) is in the confirmed close group.
    #[must_use]
    pub fn contains(&self, peer_id_hex: &str) -> bool {
        self.members.iter().any(|m| m == peer_id_hex)
    }

    /// Return how many of the confirmed members overlap with a given set.
    #[must_use]
    pub fn overlap_count(&self, other: &[String]) -> usize {
        self.members.iter().filter(|m| other.contains(m)).count()
    }

    /// Return the overlap ratio with a given set (0.0 to 1.0).
    #[must_use]
    pub fn overlap_ratio(&self, other: &[String]) -> f64 {
        if self.members.is_empty() || other.is_empty() {
            return 0.0;
        }
        let overlap = self.overlap_count(other);
        let max_len = self.members.len().max(other.len());
        #[allow(clippy::cast_precision_loss)]
        {
            overlap as f64 / max_len as f64
        }
    }
}

/// Perform a confirmed close group lookup.
///
/// Queries `num_lookups` different nodes for the closest peers to `target`,
/// then returns peers that appeared in at least `threshold` of those lookups.
///
/// # Arguments
///
/// * `nodes` - The P2P nodes to query from (will use up to `num_lookups` of them)
/// * `target` - The `XorName` address to find closest nodes for
/// * `k` - How many closest nodes to request per lookup
/// * `num_lookups` - How many independent lookups to perform
/// * `threshold` - Minimum number of lookups a peer must appear in to be confirmed
pub async fn confirm_close_group(
    nodes: &[Arc<P2PNode>],
    target: &XorName,
    k: usize,
    num_lookups: usize,
    threshold: usize,
) -> ConfirmedCloseGroup {
    let actual_lookups = num_lookups.min(nodes.len());

    if actual_lookups == 0 || nodes.is_empty() {
        return ConfirmedCloseGroup {
            members: Vec::new(),
            num_lookups: 0,
            num_responses: 0,
            threshold,
        };
    }

    let mut appearance_count: HashMap<String, usize> = HashMap::new();
    let mut num_responses = 0usize;

    // Select which nodes to query — spread across the list
    let step = if nodes.len() > actual_lookups {
        nodes.len() / actual_lookups
    } else {
        1
    };

    for i in 0..actual_lookups {
        let node_idx = (i * step) % nodes.len();
        let Some(p2p) = nodes.get(node_idx) else {
            continue;
        };

        match tokio::time::timeout(
            CONFIRMATION_LOOKUP_TIMEOUT,
            p2p.dht().find_closest_nodes(target, k),
        )
        .await
        {
            Ok(Ok(peers)) if !peers.is_empty() => {
                num_responses += 1;
                for peer in &peers {
                    let hex = peer.peer_id.to_hex();
                    *appearance_count.entry(hex).or_insert(0) += 1;
                }
            }
            Ok(Ok(_)) => {
                debug!("Close group confirmation: node {node_idx} returned empty results");
            }
            Ok(Err(e)) => {
                warn!("Close group confirmation: node {node_idx} DHT error: {e}");
            }
            Err(_) => {
                warn!("Close group confirmation: node {node_idx} lookup timed out");
            }
        }
    }

    // Filter to peers that appeared in at least `threshold` lookups
    let mut confirmed: Vec<String> = appearance_count
        .into_iter()
        .filter(|(_, count)| *count >= threshold)
        .map(|(peer_id, _)| peer_id)
        .collect();

    // Sort by XOR distance to target
    confirmed.sort_by(|a, b| {
        let a_xor = peer_id_to_xor_name(a).map(|x| xor_distance(target, &x));
        let b_xor = peer_id_to_xor_name(b).map(|x| xor_distance(target, &x));
        match (a_xor, b_xor) {
            (Some(a_dist), Some(b_dist)) => a_dist.cmp(&b_dist),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
    });

    // Trim to the requested size, capped at close group size
    confirmed.truncate(k.min(CLOSE_GROUP_SIZE));

    ConfirmedCloseGroup {
        members: confirmed,
        num_lookups: actual_lookups,
        num_responses,
        threshold,
    }
}

/// Check if a node is likely in the close group for a given address.
///
/// Performs a single DHT lookup from the given node and checks if the node
/// itself would be among the K closest. This is the "am I responsible for
/// this address?" check that nodes should perform during verification.
pub async fn is_node_in_close_group(node: &P2PNode, target: &XorName) -> bool {
    let my_peer_id = node.peer_id().to_hex();
    let Some(my_xor) = peer_id_to_xor_name(&my_peer_id) else {
        return false;
    };
    let my_distance = xor_distance(target, &my_xor);

    match tokio::time::timeout(
        CONFIRMATION_LOOKUP_TIMEOUT,
        node.dht().find_closest_nodes(target, CLOSE_GROUP_SIZE),
    )
    .await
    {
        Ok(Ok(peers)) => {
            // If we couldn't retrieve a full close group, we can't confirm
            // responsibility — treat as "not in close group" so the PUT is
            // rejected or retried rather than silently accepted.
            if peers.len() < CLOSE_GROUP_SIZE {
                warn!(
                    "is_node_in_close_group: only found {} peers (need {CLOSE_GROUP_SIZE})",
                    peers.len()
                );
                return false;
            }

            // Check if we're closer than the furthest member
            let furthest_distance = peers
                .iter()
                .filter_map(|p| peer_id_to_xor_name(&p.peer_id.to_hex()))
                .map(|xor| xor_distance(target, &xor))
                .max();

            furthest_distance.is_some_and(|furthest| my_distance <= furthest)
        }
        Ok(Err(e)) => {
            warn!("is_node_in_close_group: DHT lookup failed: {e}");
            false
        }
        Err(_) => {
            warn!("is_node_in_close_group: DHT lookup timed out");
            false
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_confirmed_close_group_contains() {
        let group = ConfirmedCloseGroup {
            members: vec!["aa".repeat(32), "bb".repeat(32)],
            num_lookups: 3,
            num_responses: 3,
            threshold: 2,
        };

        assert!(group.contains(&"aa".repeat(32)));
        assert!(!group.contains(&"cc".repeat(32)));
    }

    #[test]
    fn test_confirmed_close_group_overlap() {
        let group = ConfirmedCloseGroup {
            members: vec!["aa".repeat(32), "bb".repeat(32), "cc".repeat(32)],
            num_lookups: 3,
            num_responses: 3,
            threshold: 2,
        };

        let other = vec!["aa".repeat(32), "cc".repeat(32), "dd".repeat(32)];
        assert_eq!(group.overlap_count(&other), 2);
    }
}
