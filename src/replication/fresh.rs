//! Fresh replication (Section 6.1).
//!
//! When a node accepts a newly written record with valid `PoP`:
//! 1. Store locally (already done by chunk handler).
//! 2. Record the key in `PaidForList(self)` and send `PaidNotify` to every
//!    peer in `PaidCloseGroup(K)` — immediately, never behind back-pressure.
//! 3. Send fresh offers to `CLOSE_GROUP_SIZE` nearest peers (excluding self),
//!    bounded by the pending-offer permits so a write burst cannot pile up
//!    chunk-sized buffers.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::logging::{debug, info, warn};
use bytes::Bytes;
use rand::Rng;
use saorsa_core::identity::PeerId;
use saorsa_core::P2PNode;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

use crate::ant_protocol::XorName;
use crate::payment::PaymentVerifier;
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
    /// The fan-out must not judge peers on this write (see
    /// [`announce_paid_write`]).
    pub(crate) contested: bool,
    /// Storage read-backs attempted so far; see `MAX_FRESH_READ_ATTEMPTS`.
    pub(crate) read_attempts: u32,
}

/// Handles shared by everything that sends fresh offers, so the offer
/// dispatcher task and the direct entry point run one pipeline.
pub(crate) struct FreshOfferContext {
    pub(crate) p2p_node: Arc<P2PNode>,
    pub(crate) config: Arc<ReplicationConfig>,
    /// Limits concurrent outbound chunk transfers across the engine.
    pub(crate) send_semaphore: Arc<Semaphore>,
    /// Delayed possession checks (ADR-0003) are scheduled here once an
    /// offer's sends are dispatched.
    pub(crate) possession_check_tx: mpsc::UnboundedSender<PossessionCheckEvent>,
    /// Offers encoded and handed to at least one per-peer send, so tests can
    /// tell a write that went out from one lost to back-pressure.
    pub(crate) dispatched: Arc<AtomicU64>,
}

/// An encoded fresh offer and the pending-offer permit it holds.
///
/// Wrapped with [`Bytes::from_owner`], so the per-peer send tasks and the
/// transport share the one buffer through reference-counted handles, and the
/// permit is released only when the last handle anywhere is dropped. That is
/// what caps the encoded offers alive at once at `MAX_PENDING_FRESH_OFFERS`.
struct EncodedOffer {
    bytes: Vec<u8>,
    _pending: OwnedSemaphorePermit,
}

impl AsRef<[u8]> for EncodedOffer {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Rule 6: a node that validates `PoP` adds K to `PaidForList(self)`, marked
/// when `mark`.
///
/// `mark` is the decision this node took when it verified the payment
/// (`PaymentVerifier::verified_payment_contested`), so a write
/// admitted from the payment cache is recorded by that decision, never by the
/// proof attached to it, which nobody checked. A contested write is marked
/// (ADR-0006) because a close-group peer may have refused it under its own
/// floor, and refusing a below-floor payment is network policy, never
/// misbehaviour. While this node holds the key, the mark keeps it from judging
/// its peers on it: the key goes out in paid hints only, so no repair proof is
/// recorded and no responsible audit samples it, and a prune audit of it
/// scores no one. Every other check that reads the mark points here.
///
/// The first record of a key decides its mark: an existing entry is never
/// changed, so a later payment can neither add nor remove it. Returns whether
/// `mark` or the key's record is marked once this call is done, whichever
/// record won: ours, or one a concurrent `PaidNotify` or fresh offer wrote
/// first. A mark that cannot be read counts as set (see
/// `PaidList::counts_as_price_contested`).
pub(crate) async fn record_paid_key(key: &XorName, mark: bool, paid_list: &PaidList) -> bool {
    let recorded = if mark {
        paid_list.insert_price_contested(key).await
    } else {
        paid_list.insert(key).await
    };
    if let Err(e) = recorded {
        warn!("Failed to add key {} to PaidForList: {e}", hex::encode(key));
    }
    mark || paid_list.counts_as_price_contested(key)
}

/// Rules 6-8: record the paid key locally (see [`record_paid_key`]) and
/// announce it to `PaidCloseGroup(K)`. Returns whether the write's fan-out
/// must leave its peers unjudged (ADR-0006).
///
/// The record is marked by the decision this node took when it verified the
/// payment. The fan-out is left unjudged when that decision or the key's
/// record is marked once recorded, whichever record won, so a marked write is
/// never judged, and also when the proof being forwarded is contested: a
/// cached PUT forwards it unverified, and its peers verify it and may refuse
/// it.
///
/// This is the evidence peers need to repair the key later, so it runs the
/// moment a write is accepted and is never gated by the pending-offer permit
/// or the send semaphore; both messages are small metadata.
pub(crate) async fn announce_paid_write(
    key: &XorName,
    proof_of_payment: &[u8],
    payment_verifier: &PaymentVerifier,
    paid_list: &PaidList,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
) -> bool {
    let marked = record_paid_key(
        key,
        payment_verifier.verified_payment_contested(key),
        paid_list,
    )
    .await;
    // Rules 7-8: PaidNotify to every member of PaidCloseGroup(K).
    send_paid_notify(key, proof_of_payment, p2p_node, config).await;
    marked
        || payment_verifier
            .price_contested(key, proof_of_payment)
            .await
}

/// Rules 2-3: send fresh offers to the close group and schedule the delayed
/// possession check (ADR-0003) for the responsible peers, unless `contested`
/// (see [`announce_paid_write`]).
///
/// `pending_offer` is the caller's permit from the pending-offer semaphore;
/// it is held with the encoded offer until the last handle to it is dropped.
/// `data` and `proof_of_payment` are taken by value so they move into the
/// offer instead of being copied.
pub(crate) async fn send_fresh_offers(
    ctx: &FreshOfferContext,
    key: &XorName,
    data: Vec<u8>,
    proof_of_payment: Vec<u8>,
    contested: bool,
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
        proof_of_payment,
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
    // One encoded copy serves every per-peer send task and every retry; the
    // transport borrows it through `Bytes` instead of taking a copy. The
    // pending-offer permit travels with the buffer.
    let encoded = Bytes::from_owner(EncodedOffer {
        bytes: encoded,
        _pending: pending_offer,
    });
    for peer in &target_peers {
        let p2p = Arc::clone(&ctx.p2p_node);
        let offer = encoded.clone();
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
                    .send_message(&peer_id, REPLICATION_PROTOCOL_ID, offer.clone(), &[])
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
    // Not for a contested write: a peer may have refused it (ADR-0006).
    if !target_peers.is_empty() {
        ctx.dispatched.fetch_add(1, Ordering::Relaxed);
        if contested {
            info!(
                "Fresh replication of {}: no possession check, the payment is contested \
                 under the price floor",
                hex::encode(key)
            );
        } else {
            let _ = ctx.possession_check_tx.send(PossessionCheckEvent {
                key: *key,
                peers: target_peers,
            });
        }
    }
}

/// Send `PaidNotify(K)` to every peer in `PaidCloseGroup(K)` (fire-and-forget).
///
/// Per Invariant 16: sender MUST attempt delivery to every member. The
/// message is small metadata (no chunk data), so it is neither gated by the
/// send semaphore nor by the pending-offer permit.
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// ADR-0006: a contested payment marks a newly recorded key, an
    /// uncontested one records it plainly, and the first record of a key
    /// decides: a later record, either way, changes nothing. Each call
    /// reports the winning record's mark, or its own when that is set, so a
    /// write whose plain decision lost to a marked record is still left
    /// unjudged.
    #[tokio::test]
    async fn the_first_record_of_a_key_decides_its_mark() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paid_list = PaidList::new(dir.path()).await.expect("paid list");
        let contested = [0x91u8; 32];
        let plain = [0x92u8; 32];

        let reported = vec![
            record_paid_key(&contested, true, &paid_list).await,
            record_paid_key(&plain, false, &paid_list).await,
            record_paid_key(&contested, false, &paid_list).await,
            record_paid_key(&plain, true, &paid_list).await,
        ];

        let marks: Vec<(bool, bool)> = [contested, plain]
            .iter()
            .map(|key| {
                (
                    paid_list.contains(key).expect("contains"),
                    paid_list.is_price_contested(key).expect("read mark"),
                )
            })
            .collect();
        assert_eq!(marks, vec![(true, true), (true, false)]);
        assert_eq!(reported, vec![true, false, true, true]);
    }

    /// ADR-0006: a plain write is left unjudged while the paid list cannot be
    /// read, since the record that won may be marked.
    #[tokio::test]
    async fn a_write_whose_mark_cannot_be_read_is_left_unjudged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paid_list = PaidList::new(dir.path()).await.expect("paid list");
        let plain = [0x93u8; 32];
        assert!(!record_paid_key(&plain, false, &paid_list).await);

        let _reader = paid_list.hold_reader_for_tests().expect("hold reader");
        assert!(record_paid_key(&plain, false, &paid_list).await);
    }

    /// The permit is released with the last handle to the encoded offer, not
    /// the first: a slice the transport still holds keeps the offer counted.
    #[test]
    fn the_pending_offer_permit_outlives_every_handle() {
        let permits = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&permits)
            .try_acquire_owned()
            .expect("free permit");
        let offer = Bytes::from_owner(EncodedOffer {
            bytes: vec![7; 16],
            _pending: permit,
        });
        let held_elsewhere = offer.slice(4..8);

        drop(offer);
        assert_eq!(permits.available_permits(), 0);
        drop(held_elsewhere);
        assert_eq!(permits.available_permits(), 1);
    }
}
