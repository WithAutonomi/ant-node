//! Fresh replication (Section 6.1).
//!
//! When a node accepts a newly written record with valid `PoP`:
//! 1. Store locally (already done by chunk handler).
//! 2. Send fresh offers to `CLOSE_GROUP_SIZE` nearest peers (excluding self).
//! 3. Send `PaidNotify` to all peers in `PaidCloseGroup(K)`.

use std::sync::Arc;

use crate::logging::{debug, warn};
use rand::Rng;
use saorsa_core::identity::PeerId;
use saorsa_core::P2PNode;

use crate::ant_protocol::XorName;
use crate::replication::config::{ReplicationConfig, REPLICATION_PROTOCOL_ID};
use crate::replication::paid_list::PaidList;
use crate::replication::protocol::{
    FreshReplicationOffer, PaidNotify, ReplicationMessage, ReplicationMessageBody,
};

/// A newly-stored chunk that needs fresh replication.
///
/// Sent from the chunk PUT handler to the replication engine via an
/// unbounded channel so that the PUT response is not blocked by
/// replication fan-out.
pub struct FreshWriteEvent {
    /// Content-address of the stored chunk.
    pub key: XorName,
    /// The chunk data.
    pub data: Vec<u8>,
    /// Serialized proof-of-payment.
    pub payment_proof: Vec<u8>,
}

/// Execute fresh replication for a newly accepted record.
///
/// Sends fresh offers to close group members and `PaidNotify` to
/// `PaidCloseGroup`. Both are fire-and-forget (no ack tracking or retry per
/// Section 6.1, rule 8).
pub async fn replicate_fresh(
    key: &XorName,
    data: &[u8],
    proof_of_payment: &[u8],
    p2p_node: &Arc<P2PNode>,
    paid_list: &Arc<PaidList>,
    config: &ReplicationConfig,
) {
    let self_id = *p2p_node.peer_id();

    // Rule 6: Node that validates PoP adds K to PaidForList(self).
    if let Err(e) = paid_list.insert(key).await {
        warn!("Failed to add key {} to PaidForList: {e}", hex::encode(key));
    }

    // Rule 2-3: Send fresh offers to CLOSE_GROUP_SIZE nearest peers
    // (excluding self). Use self-inclusive query to get the true close group,
    // then filter self out.
    let closest = p2p_node
        .dht_manager()
        .find_closest_nodes_local_with_self(key, config.close_group_size)
        .await;
    let target_peers: Vec<PeerId> = closest
        .iter()
        .filter(|n| n.peer_id != self_id)
        .map(|n| n.peer_id)
        .collect();

    let offer = FreshReplicationOffer {
        key: *key,
        data: data.to_vec(),
        proof_of_payment: proof_of_payment.to_vec(),
    };
    let request_id = rand::thread_rng().gen::<u64>();
    let offer_msg = ReplicationMessage {
        request_id,
        body: ReplicationMessageBody::FreshReplicationOffer(offer),
    };

    let Ok(encoded) = offer_msg.encode() else {
        warn!(
            "Failed to encode FreshReplicationOffer for {}",
            hex::encode(key),
        );
        return;
    };
    for peer in &target_peers {
        let p2p = Arc::clone(p2p_node);
        let data = encoded.clone();
        let peer_id = *peer;
        tokio::spawn(async move {
            if let Err(e) = p2p
                .send_message(&peer_id, REPLICATION_PROTOCOL_ID, data, &[])
                .await
            {
                debug!("Failed to send fresh offer to {peer_id}: {e}");
            }
        });
    }

    // Rule 7-8: Send PaidNotify to every member of PaidCloseGroup(K).
    send_paid_notify(key, proof_of_payment, p2p_node, config).await;

    debug!(
        "Fresh replication initiated for {} to {} peers + PaidNotify",
        hex::encode(key),
        target_peers.len()
    );
}

/// Send `PaidNotify(K)` to every peer in `PaidCloseGroup(K)` (fire-and-forget).
///
/// Per Invariant 16: sender MUST attempt delivery to every member.
async fn send_paid_notify(
    key: &XorName,
    proof_of_payment: &[u8],
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
) {
    let self_id = *p2p_node.peer_id();
    let paid_group = p2p_node
        .dht_manager()
        .find_closest_nodes_local_with_self(key, config.paid_list_close_group_size)
        .await;

    let notify = PaidNotify {
        key: *key,
        proof_of_payment: proof_of_payment.to_vec(),
    };
    let request_id = rand::thread_rng().gen::<u64>();
    let msg = ReplicationMessage {
        request_id,
        body: ReplicationMessageBody::PaidNotify(notify),
    };

    let Ok(encoded) = msg.encode() else {
        warn!("Failed to encode PaidNotify for {}", hex::encode(key));
        return;
    };

    for node in &paid_group {
        if node.peer_id == self_id {
            continue;
        }
        let p2p = Arc::clone(p2p_node);
        let data = encoded.clone();
        let peer_id = node.peer_id;
        tokio::spawn(async move {
            if let Err(e) = p2p
                .send_message(&peer_id, REPLICATION_PROTOCOL_ID, data, &[])
                .await
            {
                debug!("Failed to send PaidNotify to {peer_id}: {e}");
            }
        });
    }
}
