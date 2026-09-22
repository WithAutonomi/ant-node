//! Fresh replication (Section 6.1).
//!
//! When a node accepts a newly written record with valid `PoP`:
//! 1. Store locally (already done by chunk handler).
//! 2. Record the key in `PaidForList(self)` and send `PaidNotify` to every
//!    peer in `PaidCloseGroup(K)` — immediately, never behind back-pressure.
//! 3. Send fresh offers to `CLOSE_GROUP_SIZE` nearest peers (excluding self),
//!    bounded by the pending-offer permits so a write burst cannot pile up
//!    chunk-sized buffers.

use std::sync::Arc;

use crate::logging::{debug, warn};
use bytes::Bytes;
use rand::Rng;
use saorsa_core::identity::PeerId;
use saorsa_core::P2PNode;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

use crate::ant_protocol::XorName;
use crate::replication::config::{
    ReplicationConfig, FRESH_REPLICATION_DELIVERY_MAX_RETRIES, REPLICATION_PROTOCOL_ID,
};
use crate::replication::paid_list::PaidList;
use crate::replication::possession::PossessionCheckEvent;
use crate::replication::protocol::{
    FreshReplicationOffer, PaidNotify, ReplicationMessage, ReplicationMessageBody,
};

/// A newly-stored chunk that needs fresh replication.
///
/// Sent from the chunk PUT handler to the replication engine via an
/// unbounded channel so that the PUT response is not blocked by
/// replication fan-out. The event deliberately carries no chunk bytes: the
/// chunk is already on disk, and the offer dispatcher reads it back only
/// once it holds a pending-offer permit, so a replication backlog queues as
/// small events rather than chunk-sized buffers.
pub struct FreshWriteEvent {
    /// Content-address of the stored chunk.
    pub key: XorName,
    /// Serialized proof-of-payment.
    pub payment_proof: Vec<u8>,
}

/// A write whose paid-list evidence has been announced and whose chunk offer
/// is waiting for a pending-offer permit. Carries no chunk bytes.
pub(crate) struct FreshOfferEvent {
    pub(crate) key: XorName,
    pub(crate) payment_proof: Vec<u8>,
    /// Storage read-backs attempted so far; see `MAX_FRESH_READ_ATTEMPTS`.
    pub(crate) read_attempts: u32,
}

/// Handles shared by everything that dispatches fresh offers, so the offer
/// dispatcher task and the direct entry point run one pipeline.
#[derive(Clone)]
pub(crate) struct FreshOfferContext {
    pub(crate) p2p_node: Arc<P2PNode>,
    pub(crate) config: Arc<ReplicationConfig>,
    /// Limits concurrent outbound chunk transfers across the engine.
    pub(crate) send_semaphore: Arc<Semaphore>,
    /// Delayed possession checks (ADR-0003) are scheduled here once an
    /// offer's sends are dispatched.
    pub(crate) possession_check_tx: mpsc::UnboundedSender<PossessionCheckEvent>,
}

/// An encoded fresh offer shared by the per-peer send tasks.
///
/// The pending-offer permit is released together with the buffer, once the
/// last send task drops its reference, which caps how many encoded offers
/// can wait behind the send permits at `MAX_PENDING_FRESH_OFFERS`. The bytes
/// are shared with the transport as well: each send attempt hands out a
/// reference-counted handle rather than a copy.
struct EncodedOffer {
    bytes: Bytes,
    _pending: OwnedSemaphorePermit,
}

/// Rules 6-8: record the paid key locally and announce it to
/// `PaidCloseGroup(K)`.
///
/// This is the evidence peers need to repair the key later, so it runs the
/// moment a write is accepted and is never gated by the pending-offer permit
/// or the send semaphore; both messages are small metadata.
pub(crate) async fn announce_paid_write(
    key: &XorName,
    proof_of_payment: &[u8],
    paid_list: &PaidList,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
) {
    // Rule 6: Node that validates PoP adds K to PaidForList(self).
    if let Err(e) = paid_list.insert(key).await {
        warn!("Failed to add key {} to PaidForList: {e}", hex::encode(key));
    }
    // Rules 7-8: PaidNotify to every member of PaidCloseGroup(K).
    send_paid_notify(key, proof_of_payment, p2p_node, config).await;
}

/// Rules 2-3: send fresh offers to the close group and schedule the delayed
/// possession check (ADR-0003) for the responsible peers.
///
/// `pending_offer` is the caller's permit from the pending-offer semaphore;
/// it is held with the encoded offer until the last per-peer send finishes.
/// `data` is taken by value so the chunk moves into the offer instead of
/// being copied.
pub(crate) async fn dispatch_fresh_offer(
    ctx: &FreshOfferContext,
    key: &XorName,
    data: Vec<u8>,
    proof_of_payment: &[u8],
    pending_offer: OwnedSemaphorePermit,
) {
    let self_id = *ctx.p2p_node.peer_id();

    // Use the self-inclusive query to get the true close group, then filter
    // self out.
    let closest = ctx
        .p2p_node
        .dht_manager()
        .find_closest_nodes_local_with_self(key, ctx.config.close_group_size)
        .await;
    let target_peers: Vec<PeerId> = closest
        .iter()
        .filter(|n| n.peer_id != self_id)
        .map(|n| n.peer_id)
        .collect();

    let offer = FreshReplicationOffer {
        key: *key,
        data,
        proof_of_payment: proof_of_payment.to_vec(),
    };
    let request_id = rand::thread_rng().gen::<u64>();
    let offer_msg = ReplicationMessage {
        request_id,
        body: ReplicationMessageBody::FreshReplicationOffer(offer),
    };

    let encoded = offer_msg.encode();
    // Only the encoded bytes are needed from here on; release the chunk now
    // rather than holding it alongside the encoding while sends are queued.
    drop(offer_msg);
    let Ok(encoded) = encoded else {
        warn!(
            "Failed to encode FreshReplicationOffer for {}",
            hex::encode(key),
        );
        return;
    };
    // One encoded copy serves every per-peer send task and every retry; the
    // transport borrows it through `Bytes` instead of taking a copy. The
    // pending-offer permit travels with the buffer.
    let encoded = Arc::new(EncodedOffer {
        bytes: Bytes::from(encoded),
        _pending: pending_offer,
    });
    for peer in &target_peers {
        let p2p = Arc::clone(&ctx.p2p_node);
        let offer = Arc::clone(&encoded);
        let peer_id = *peer;
        let sem = Arc::clone(&ctx.send_semaphore);
        tokio::spawn(async move {
            // Acquire a permit before sending — this caps the number of
            // concurrent outbound replication transfers across the engine.
            let _permit = sem.acquire().await;
            debug!(
                "Replication send permit acquired for peer {peer_id} ({} available)",
                sem.available_permits()
            );
            // ADR-0003: best-effort delivery. Retry the push up to
            // FRESH_REPLICATION_DELIVERY_MAX_RETRIES times on a transport
            // failure so a transient hiccup doesn't silently drop the offer.
            // Possession is judged separately by the delayed possession check.
            let mut attempt = 0u32;
            loop {
                match p2p
                    .send_message(&peer_id, REPLICATION_PROTOCOL_ID, offer.bytes.clone(), &[])
                    .await
                {
                    Ok(()) => break,
                    Err(e) => {
                        if attempt >= FRESH_REPLICATION_DELIVERY_MAX_RETRIES {
                            debug!(
                                "Failed to send fresh offer to {peer_id} after {} attempts: {e}",
                                attempt + 1
                            );
                            break;
                        }
                        attempt += 1;
                        debug!(
                            "Retrying fresh offer to {peer_id} (attempt {}): {e}",
                            attempt + 1
                        );
                    }
                }
            }
        });
    }

    debug!(
        "Fresh replication initiated for {} to {} peers",
        hex::encode(key),
        target_peers.len()
    );

    // Schedule the delayed possession check (ADR-0003) for the responsible
    // close-group peers. A closed receiver (engine shutting down) is ignored.
    if !target_peers.is_empty() {
        let _ = ctx.possession_check_tx.send(PossessionCheckEvent {
            key: *key,
            peers: target_peers,
        });
    }
}

/// Send `PaidNotify(K)` to every peer in `PaidCloseGroup(K)` (fire-and-forget).
///
/// Per Invariant 16: sender MUST attempt delivery to every member. The
/// message is small metadata (no chunk data), so it is neither gated by the
/// send semaphore nor by the pending-offer permit.
pub(crate) async fn send_paid_notify(
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
    // One buffer for every recipient; the sends only take handles.
    let encoded = Bytes::from(encoded);
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
