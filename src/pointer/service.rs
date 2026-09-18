//! The node's pointer request handler.
//!
//! Sits between the wire messages in [`ant_protocol::chunk`] and the
//! [`PointerStore`], and owns the three things a pointer PUT needs that a chunk
//! PUT does not:
//!
//! 1. **Payment at `state_id`, not at the address.** A pointer's address is
//!    stable for its life, so quoting against it would make every update after
//!    the first free — 1.0's defect. The quote's content is the state
//!    identifier; the close group that answers is still the one around the
//!    address.
//! 2. **Merge instead of "already exists".** The chunk path answers
//!    `AlreadyExists` and stops, which for a mutable record silently drops
//!    every update.
//! 3. **Cross-kind collision refusal.** A pointer address and a chunk address
//!    are both 32 bytes from the same range; the domain separator makes a
//!    collision infeasible, not impossible. A node that holds one kind at an
//!    address refuses the other rather than silently choosing.
//!
//! # Order of work
//!
//! ```text
//! parse → compare with what is held → verify signature → check payment → commit
//! ```
//!
//! The comparison precedes the signature check, so re-submitting a state the
//! node already holds costs a parse and a map lookup rather than an ML-DSA
//! verification. The payment check sits between validation and commit, and the
//! commit re-checks, because a newer state can land while payment is verified.

use std::sync::Arc;

use ant_protocol::chunk::{
    PointerGetRequest, PointerGetResponse, PointerPutRequest, PointerPutResponse, ProtocolError,
    XorName,
};
use bytes::Bytes;
use parking_lot::RwLock;
use saorsa_core::P2PNode;

use crate::error::{Error, Result};
use crate::logging::{debug, warn};
use crate::payment::PaymentVerifier;
use crate::pointer::store::{Inspected, PointerStore, PutOutcome};
use crate::replication::admission;
use crate::storage::{ChunkStore, SELF_CLOSENESS_GATE_WIDTH};

/// Handles pointer requests against a [`PointerStore`].
#[derive(Clone)]
pub struct PointerService {
    /// Where pointers are kept.
    store: PointerStore,
    /// Consulted so an address held as a chunk is never overwritten by a
    /// pointer.
    chunks: Option<Arc<ChunkStore>>,
    /// Confirms a state was paid for. `None` in tests that exercise the merge
    /// rather than the payment.
    payments: Option<Arc<PaymentVerifier>>,
    /// The node's P2P handle, for the self-closeness gate.
    ///
    /// Attached after construction, because the node builds its protocol
    /// handler before it has a running P2P node. `None` in unit tests that
    /// never attach one, exactly as the chunk path does.
    p2p_node: Arc<RwLock<Option<Arc<P2PNode>>>>,
}

impl std::fmt::Debug for PointerService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PointerService")
            .field("records", &self.store.len())
            .field("checks_chunk_collisions", &self.chunks.is_some())
            .field("verifies_payment", &self.payments.is_some())
            .finish_non_exhaustive()
    }
}

impl PointerService {
    /// Build a service over `store`.
    #[must_use]
    pub fn new(store: PointerStore) -> Self {
        Self {
            store,
            chunks: None,
            payments: None,
            p2p_node: Arc::new(RwLock::new(None)),
        }
    }

    /// Apply the self-closeness gate, so a pointer PUT is admitted only where
    /// the node is actually responsible.
    ///
    /// Without it one valid proof can be replayed to every node on the network,
    /// each of which would store the record and trigger replication for an
    /// address it has no business holding.
    pub fn attach_p2p_node(&self, p2p_node: Arc<P2PNode>) {
        *self.p2p_node.write() = Some(p2p_node);
    }

    /// Consult `chunks` before storing, so a cross-kind address collision is
    /// refused rather than resolved by whichever kind arrived last.
    #[must_use]
    pub fn with_chunk_store(mut self, chunks: Arc<ChunkStore>) -> Self {
        self.chunks = Some(chunks);
        self
    }

    /// Require payment, verified against each record's `state_id`.
    #[must_use]
    pub fn with_payments(mut self, payments: Arc<PaymentVerifier>) -> Self {
        self.payments = Some(payments);
        self
    }

    /// The store this service fronts.
    #[must_use]
    pub const fn store(&self) -> &PointerStore {
        &self.store
    }

    /// Handle a pointer PUT.
    ///
    /// Never returns `Err`: a rejection is a response the peer should see, so
    /// every failure is mapped onto [`PointerPutResponse`].
    pub async fn handle_put(&self, request: PointerPutRequest) -> PointerPutResponse {
        // Cheap first: parse and compare against what is held. No signature is
        // checked yet, so a forged record for an address this node does not
        // serve is rejected by the gates below without buying an ML-DSA
        // verification.
        let parsed = match self.store.inspect(&request.record) {
            Ok(Inspected::Noop(PutOutcome::Unchanged)) => {
                return match Self::state_of(&request.record) {
                    Some((address, state_id)) => {
                        PointerPutResponse::Unchanged { address, state_id }
                    }
                    None => PointerPutResponse::Error(ProtocolError::Internal(
                        "pointer parsed then failed to re-parse".to_string(),
                    )),
                };
            }
            Ok(Inspected::Noop(PutOutcome::Stale)) => {
                let Some((address, _)) = Self::state_of(&request.record) else {
                    return PointerPutResponse::Error(ProtocolError::Internal(
                        "pointer parsed then failed to re-parse".to_string(),
                    ));
                };
                let held = self.store.state_id(&address).unwrap_or_default();
                return PointerPutResponse::Stale {
                    address,
                    state_id: held,
                };
            }
            Ok(Inspected::Noop(other)) => {
                return PointerPutResponse::Error(ProtocolError::Internal(format!(
                    "unexpected no-op outcome {other:?}"
                )));
            }
            Ok(Inspected::Candidate(parsed)) => parsed,
            Err(e) => {
                debug!("Pointer PUT refused: {e}");
                return PointerPutResponse::Error(ProtocolError::StorageFailed(e.to_string()));
            }
        };

        let address = parsed.state().address;
        let state_id = parsed.state().state_id;

        if let Some(refusal) = self.admit(parsed.state()).await {
            return refusal;
        }

        // Only now is the record worth a signature check.
        let prepared = match self.store.verify(parsed).await {
            Ok(prepared) => prepared,
            Err(e) => {
                debug!("Pointer PUT refused: {e}");
                return PointerPutResponse::Error(ProtocolError::StorageFailed(e.to_string()));
            }
        };

        // Payment is checked against the state, not the address: the address
        // never changes, so paying against it would buy every future update.
        if let Some(payments) = &self.payments {
            if let Err(e) =
                Self::verify_payment(payments, address, state_id, request.payment_proof.as_ref())
                    .await
            {
                return PointerPutResponse::PaymentRequired {
                    message: e.to_string(),
                };
            }
        }

        match self.store.commit(prepared).await {
            Ok(PutOutcome::Stored | PutOutcome::Replaced) => {
                PointerPutResponse::Success { address, state_id }
            }
            // The re-check under the commit lock found a newer state. The
            // client paid for a state that lost a race; say so plainly.
            Ok(PutOutcome::Unchanged) => PointerPutResponse::Unchanged { address, state_id },
            Ok(PutOutcome::Stale) => PointerPutResponse::Stale {
                address,
                state_id: self.store.state_id(&address).unwrap_or(state_id),
            },
            Err(e) => {
                warn!("Pointer commit failed for {}: {e}", hex::encode(address));
                PointerPutResponse::Error(ProtocolError::StorageFailed(e.to_string()))
            }
        }
    }

    /// Everything that must hold before a record is worth verifying.
    ///
    /// `Some(response)` means refuse. Ordered cheapest first, and all of it
    /// ahead of the signature check, so a forged record for an address this
    /// node does not serve buys no cryptography.
    async fn admit(
        &self,
        state: &ant_protocol::pointer::PointerState,
    ) -> Option<PointerPutResponse> {
        let address = state.address;

        // One payment buys one increment. A create is counter 0 and an update
        // is exactly one past what this node holds; anything else would let an
        // owner pay once and jump the counter, skipping every intermediate
        // payment. Replication does not come through here — it merges on the
        // counter order, so a replica behind a gap can still catch up.
        if !self.store.accepts_as_paid_update(state) {
            debug!(
                "Rejecting pointer PUT for {}: counter {} is not the paid successor",
                hex::encode(address),
                state.counter
            );
            return Some(PointerPutResponse::PaymentRequired {
                message: format!(
                    "a pointer is created at counter 0 and updated by exactly one \
                     increment; counter {} does not follow what this node holds",
                    state.counter
                ),
            });
        }

        if let Some(chunks) = &self.chunks {
            // A chunk already here means the two kinds collided. Refuse rather
            // than pick: whichever we chose, someone's data would vanish.
            if let Some(refusal) = cross_kind_refusal(address, chunks.exists(&address)) {
                return Some(refusal);
            }
            // Capacity before payment, as the chunk path does.
            if let Err(e) = chunks.check_capacity() {
                debug!("Rejecting pointer PUT for {}: {e}", hex::encode(address));
                return Some(PointerPutResponse::Error(ProtocolError::StorageFailed(
                    e.to_string(),
                )));
            }
        }

        // Self-closeness gate (ADR-0003), judged at the pointer's address
        // because that is what the network routes on. Bind the handle out of
        // the lock first: no guard may be held across an await.
        let attached = self.p2p_node.read().as_ref().map(Arc::clone);
        if let Some(p2p) = attached {
            let self_id = *p2p.peer_id();
            if !admission::is_responsible(&self_id, &address, &p2p, SELF_CLOSENESS_GATE_WIDTH).await
            {
                debug!(
                    "Rejecting pointer PUT for {}: not within local closest peers",
                    hex::encode(address)
                );
                return Some(PointerPutResponse::Error(ProtocolError::StorageFailed(
                    "node is not within its local closest peers for this address".to_string(),
                )));
            }
        }
        None
    }

    /// Handle a pointer GET.
    pub async fn handle_get(&self, request: PointerGetRequest) -> PointerGetResponse {
        // A replica asking "anything newer than this?" gets a cheap index
        // lookup first, but the answer is confirmed against the file before it
        // is sent: an index entry for a record whose file has since gone or
        // stopped validating would otherwise answer "unchanged" forever, and
        // the peer would never fetch the copy that would repair it. `get`
        // re-validates and drops such an entry, so the confirmation costs a
        // read exactly once, on the way to telling the truth.
        let known = request.known_state_id;
        if known.is_some_and(|known| self.store.holds_state(&request.address, &known)) {
            match self.store.get(&request.address).await {
                Ok(Some(record)) if Some(record.state_id()) == known => {
                    return PointerGetResponse::Unchanged {
                        state_id: record.state_id(),
                    };
                }
                Ok(_) => {}
                Err(e) => {
                    return PointerGetResponse::Error(ProtocolError::StorageFailed(e.to_string()));
                }
            }
        }

        match self.store.get(&request.address).await {
            Ok(Some(record)) => PointerGetResponse::Success {
                record: Bytes::from(record.to_bytes()),
            },
            Ok(None) => PointerGetResponse::NotFound {
                address: request.address,
            },
            Err(e) => PointerGetResponse::Error(ProtocolError::StorageFailed(e.to_string())),
        }
    }

    /// Confirm the submitted state was paid for.
    ///
    /// `routing_address` selects the close group whose quotes count;
    /// `paid_content` is what the quote must name. They are different values
    /// here, which is the whole point — the existing chunk path passes one
    /// address for both jobs.
    async fn verify_payment(
        payments: &PaymentVerifier,
        routing_address: XorName,
        paid_content: XorName,
        proof: Option<&Vec<u8>>,
    ) -> Result<()> {
        let Some(proof) = proof else {
            return Err(Error::Payment(format!(
                "a pointer update must be paid for; no proof supplied for state {}",
                hex::encode(paid_content)
            )));
        };
        payments
            .verify_pointer_payment(&routing_address, &paid_content, proof)
            .await
    }

    /// Re-read the address and state a record claims, for a response.
    fn state_of(record: &[u8]) -> Option<(XorName, XorName)> {
        ant_protocol::pointer::PointerState::parse(record)
            .ok()
            .map(|state| (state.address, state.state_id))
    }
}

/// Decide whether a chunk already at `address` blocks this pointer.
///
/// Separated from the handler because the branch cannot be reached in a test
/// any other way: a pointer address is `BLAKE3(domain || owner)` and a chunk
/// address is `BLAKE3(content)`, so occupying both with real data would take an
/// actual hash collision. The decision is what matters, so the decision is what
/// is tested.
///
/// `Some(response)` means refuse. Refusing is the only safe answer: whichever
/// kind were chosen, the other's data would be destroyed, and the node cannot
/// know which one the network expects.
fn cross_kind_refusal(address: XorName, chunk_present: Result<bool>) -> Option<PointerPutResponse> {
    match chunk_present {
        Ok(true) => {
            warn!(
                "Refusing pointer at {}: a chunk already occupies that address",
                hex::encode(address)
            );
            Some(PointerPutResponse::Error(ProtocolError::StorageFailed(
                format!(
                    "address {} is already occupied by a chunk; refusing to store a \
                     pointer over it",
                    hex::encode(address)
                ),
            )))
        }
        Ok(false) => None,
        Err(e) => Some(PointerPutResponse::Error(ProtocolError::StorageFailed(
            format!("cannot check the chunk store for a collision: {e}"),
        ))),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]
mod tests {
    use super::*;
    use ant_protocol::pointer::{Pointer, PointerTarget, PointerTargetKind};
    use saorsa_pqc::api::sig::{ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey};

    fn keypair(seed: u8) -> (MlDsaPublicKey, MlDsaSecretKey) {
        ml_dsa_65().generate_keypair_from_seed(&[seed; 32])
    }

    fn signed(seed: u8, counter: u64, target_byte: u8) -> Pointer {
        let (pk, sk) = keypair(seed);
        let target = PointerTarget::new(PointerTargetKind::Chunk, [target_byte; 32]);
        Pointer::sign(&sk, &pk, counter, target).expect("sign")
    }

    async fn service() -> (PointerService, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PointerStore::new(dir.path()).await.expect("store");
        (PointerService::new(store), dir)
    }

    fn put(record: &Pointer) -> PointerPutRequest {
        PointerPutRequest::new(Bytes::from(record.to_bytes()))
    }

    #[tokio::test]
    async fn a_put_then_a_get_round_trips_the_record() {
        let (service, _dir) = service().await;
        let record = signed(1, 0, 1);

        match service.handle_put(put(&record)).await {
            PointerPutResponse::Success { address, state_id } => {
                assert_eq!(address, record.address());
                assert_eq!(state_id, record.state_id());
            }
            other => panic!("expected Success, got {other:?}"),
        }

        match service
            .handle_get(PointerGetRequest::new(record.address()))
            .await
        {
            PointerGetResponse::Success { record: bytes } => {
                assert_eq!(bytes.as_ref(), record.to_bytes());
            }
            other => panic!("expected Success, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_update_replaces_and_a_stale_one_is_told_so() {
        let (service, _dir) = service().await;
        let first = signed(1, 0, 1);
        let second = signed(1, 1, 1);
        service.handle_put(put(&first)).await;

        assert!(matches!(
            service.handle_put(put(&second)).await,
            PointerPutResponse::Success { .. }
        ));

        match service.handle_put(put(&first)).await {
            PointerPutResponse::Stale { address, state_id } => {
                assert_eq!(address, first.address());
                assert_eq!(state_id, second.state_id(), "the newer state is reported");
            }
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn re_submitting_a_held_state_is_unchanged_not_success() {
        // A client that retries must be able to tell "your update landed" from
        // "you paid for something already stored".
        let (service, _dir) = service().await;
        let record = signed(1, 0, 4);
        service.handle_put(put(&record)).await;

        let variant = signed(1, 0, 4);
        assert_ne!(variant.to_bytes(), record.to_bytes());
        match service.handle_put(put(&variant)).await {
            PointerPutResponse::Unchanged { address, state_id } => {
                assert_eq!(address, record.address());
                assert_eq!(state_id, record.state_id());
            }
            other => panic!("expected Unchanged, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_conditional_get_skips_the_transfer_when_nothing_changed() {
        let (service, _dir) = service().await;
        let record = signed(1, 0, 3);
        service.handle_put(put(&record)).await;

        match service
            .handle_get(PointerGetRequest::if_changed(
                record.address(),
                record.state_id(),
            ))
            .await
        {
            PointerGetResponse::Unchanged { state_id } => {
                assert_eq!(state_id, record.state_id());
            }
            other => panic!("expected Unchanged, got {other:?}"),
        }

        // A stale known state still gets the bytes.
        match service
            .handle_get(PointerGetRequest::if_changed(record.address(), [0u8; 32]))
            .await
        {
            PointerGetResponse::Success { .. } => {}
            other => panic!("expected Success, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_absent_pointer_is_not_found() {
        let (service, _dir) = service().await;
        match service.handle_get(PointerGetRequest::new([7u8; 32])).await {
            PointerGetResponse::NotFound { address } => assert_eq!(address, [7u8; 32]),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn junk_is_refused_rather_than_stored() {
        let (service, _dir) = service().await;
        assert!(matches!(
            service
                .handle_put(PointerPutRequest::new(Bytes::from_static(b"not a pointer")))
                .await,
            PointerPutResponse::Error(_)
        ));
        assert!(service.store().is_empty());
    }

    #[tokio::test]
    async fn a_forged_signature_is_refused() {
        let (service, _dir) = service().await;
        let record = signed(1, 0, 1);
        let mut bytes = record.to_bytes().to_vec();
        if let Some(byte) = bytes.get_mut(ant_protocol::pointer::POINTER_BODY_LEN + 3) {
            *byte ^= 0xff;
        }
        assert!(matches!(
            service
                .handle_put(PointerPutRequest::new(Bytes::from(bytes)))
                .await,
            PointerPutResponse::Error(_)
        ));
        assert!(service.store().is_empty());
    }

    #[tokio::test]
    async fn payment_is_required_when_a_verifier_is_attached() {
        use crate::payment::{PaymentVerifier, PaymentVerifierConfig};

        let dir = tempfile::tempdir().expect("tempdir");
        let store = PointerStore::new(dir.path()).await.expect("store");
        let verifier = Arc::new(PaymentVerifier::new(PaymentVerifierConfig {
            evm: Default::default(),
            cache_capacity: 16,
            close_group_size: ant_protocol::chunk::CLOSE_GROUP_SIZE,
            local_rewards_address: evmlib::common::Address::new([1u8; 20]),
            price_floor: Default::default(),
        }));
        let service = PointerService::new(store).with_payments(verifier);

        // No proof at all: refused as PaymentRequired, not stored.
        match service.handle_put(put(&signed(1, 0, 1))).await {
            PointerPutResponse::PaymentRequired { message } => {
                assert!(message.contains("must be paid for"), "got: {message}");
            }
            other => panic!("expected PaymentRequired, got {other:?}"),
        }
        assert!(
            service.store().is_empty(),
            "an unpaid update must not be stored"
        );
    }

    #[tokio::test]
    async fn a_pointer_is_created_at_zero_and_updated_one_step_at_a_time() {
        let (service, _dir) = service().await;

        // A create must be counter 0.
        assert!(matches!(
            service.handle_put(put(&signed(1, 5, 1))).await,
            PointerPutResponse::PaymentRequired { .. }
        ));
        assert!(service.store().is_empty(), "nothing was stored");

        let created = signed(1, 0, 1);
        assert!(matches!(
            service.handle_put(put(&created)).await,
            PointerPutResponse::Success { .. }
        ));

        // A jump is refused however large, including the terminal counter.
        for jump in [0u64, 2, 3, 99, u64::MAX] {
            assert!(
                matches!(
                    service.handle_put(put(&signed(1, jump, 2))).await,
                    PointerPutResponse::PaymentRequired { .. } | PointerPutResponse::Stale { .. }
                ),
                "counter {jump} must not be accepted after 0"
            );
        }

        // Exactly one increment lands.
        assert!(matches!(
            service.handle_put(put(&signed(1, 1, 2))).await,
            PointerPutResponse::Success { .. }
        ));
        let held = service
            .store()
            .get(&created.address())
            .await
            .expect("get")
            .expect("present");
        assert_eq!(held.counter(), 1);
    }

    #[test]
    fn a_pointer_is_refused_where_a_chunk_already_sits() {
        // The two kinds share one 32-byte address space. A collision is
        // infeasible, not impossible, and silently picking one would destroy
        // the other's data.
        let address = [3u8; 32];
        match cross_kind_refusal(address, Ok(true)) {
            Some(PointerPutResponse::Error(ProtocolError::StorageFailed(message))) => {
                assert!(
                    message.contains("already occupied by a chunk"),
                    "got: {message}"
                );
            }
            other => panic!("a collision must be refused, got {other:?}"),
        }
    }

    #[test]
    fn a_free_address_is_not_refused() {
        assert!(cross_kind_refusal([3u8; 32], Ok(false)).is_none());
    }

    #[test]
    fn an_unreadable_chunk_store_refuses_rather_than_assumes() {
        // "I could not check" must not be treated as "nothing is there".
        let refusal = cross_kind_refusal([3u8; 32], Err(Error::Storage("disk gone".into())));
        match refusal {
            Some(PointerPutResponse::Error(ProtocolError::StorageFailed(message))) => {
                assert!(message.contains("cannot check"), "got: {message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}
