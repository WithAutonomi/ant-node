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
//! 4. **A look before a final state.** A state at the final counter is
//!    replaced by nothing, so a node that takes one can never be corrected.
//!    Before taking one it neither holds nor lost, the node asks its close
//!    group whether a *different* final state is already held there, and
//!    refuses if a peer proves one with the signed record (ADR-0018). That is
//!    what keeps a former owner from handing an address over a second time to
//!    a node that had not heard of the first, whenever a peer can prove the
//!    first in time. A proven loser is remembered and refused again before its
//!    signature is checked.
//!
//! # Order of work
//!
//! ```text
//! parse → compare with what is held → (final state only) a proven loser?
//!       → verify signature → check payment
//!       → (final state only) ask the close group → commit
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
use futures::future::BoxFuture;
use parking_lot::RwLock;
use saorsa_core::P2PNode;
use tokio::sync::mpsc;

use crate::error::{Error, Result};
use crate::logging::{debug, info, warn};
use crate::payment::PaymentVerifier;
use crate::pointer::store::{Inspected, PointerStore, PutOutcome};
use crate::replication::admission;
use crate::replication::pointer::PointerFreshWrite;
use crate::storage::{ChunkStore, SELF_CLOSENESS_GATE_WIDTH};
use ant_protocol::pointer::{PointerState, POINTER_WIRE_LEN};

/// Where a node looks, before it takes a final state, for a different final
/// state its close group already holds (ADR-0018).
///
/// A trait rather than the replication engine itself, because the engine is
/// built after this service and needs a running P2P node, and because what the
/// service decides from the answer is worth testing without one.
pub trait FinalStateWitness: Send + Sync {
    /// Ask the close group whether a final state other than `state` is
    /// already held at `state.address`.
    fn check_final<'a>(&'a self, state: &'a PointerState) -> BoxFuture<'a, FinalityCheck>;

    /// A final state at `state.address`, other than `state`, that an earlier
    /// check already proved, without asking anyone.
    ///
    /// Cheap enough to consult ahead of the signature check, so a final state
    /// that lost once is refused again for nothing, however often the same
    /// paid record is replayed.
    fn proven_conflict(&self, state: &PointerState) -> Option<PointerState>;

    /// Forget that a look found `state` clear: the write it cleared did not
    /// land, so a retry must look again rather than reuse the answer.
    fn forget_clear(&self, state: &PointerState);
}

/// What a close group said about a final state a node is about to take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalityCheck {
    /// No peer proved a different final state. Also the answer when the group
    /// could not be asked in time: silence is not evidence, so it never
    /// refuses a write.
    Clear,
    /// A different final state a peer holds, proven by the signed record,
    /// which only the owner could have made.
    Conflict(PointerState),
    /// Too many checks were running to start this one in time. The state is
    /// neither taken nor refused for good, and the sender may try again.
    Busy,
}

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
    /// Where a newly stored paid state goes to be offered to the rest of its
    /// close group (ADR-0016 replication). Attached once the replication
    /// engine exists, which is after this service is built; empty where
    /// nothing replicates, as in unit tests and the devnet.
    fresh_writes: Arc<RwLock<Option<mpsc::UnboundedSender<PointerFreshWrite>>>>,
    /// The node's P2P handle, for the self-closeness gate.
    ///
    /// Attached after construction, because the node builds its protocol
    /// handler before it has a running P2P node. `None` in unit tests that
    /// never attach one, exactly as the chunk path does.
    p2p_node: Arc<RwLock<Option<Arc<P2PNode>>>>,
    /// Asked before a final state is taken (ADR-0018). Attached with the
    /// replication engine; `None` where nothing replicates, and then a final
    /// state is taken on the merge rule alone.
    final_witness: Arc<RwLock<Option<Arc<dyn FinalStateWitness>>>>,
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
            fresh_writes: Arc::new(RwLock::new(None)),
            p2p_node: Arc::new(RwLock::new(None)),
            final_witness: Arc::new(RwLock::new(None)),
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

    /// Hand every newly stored paid state to replication on `writes`.
    pub fn attach_fresh_writes(&self, writes: mpsc::UnboundedSender<PointerFreshWrite>) {
        *self.fresh_writes.write() = Some(writes);
    }

    /// Ask `witness` before taking a final state this node does not hold.
    pub fn attach_final_state_witness(&self, witness: Arc<dyn FinalStateWitness>) {
        *self.final_witness.write() = Some(witness);
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
        let parsed = match self.store.inspect(&request.record).await {
            Ok(Inspected::Unchanged(state)) => {
                return PointerPutResponse::Unchanged {
                    address: state.address,
                    state_id: state.state_id,
                };
            }
            Ok(Inspected::Stale(state)) => {
                // The state named is the one this node keeps, not the one that
                // arrived: it is what the sender needs in order to catch up.
                return PointerPutResponse::Stale {
                    address: state.address,
                    state_id: self.store.state_id(&state.address).unwrap_or_default(),
                };
            }
            Ok(Inspected::Candidate(parsed)) => parsed,
            Err(e) => {
                debug!("Pointer PUT refused: {e}");
                return PointerPutResponse::Error(ProtocolError::StorageFailed(e.to_string()));
            }
        };

        let state = *parsed.state();
        let address = state.address;
        let state_id = state.state_id;

        if let Some(refusal) = self.admit(&state).await {
            return refusal;
        }

        // Only now is the record worth a signature check.
        let record = match self.store.verify(parsed).await {
            Ok(record) => record,
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

        // Last, because it costs the close group a round trip, and only for a
        // paid final state: if a peer proves a different final state is
        // already held, this one lost the race to it everywhere that matters.
        if let Some(refusal) = self.final_refusal(&state).await {
            return refusal;
        }

        // Charge the bytes this write will take, and hold the charge until it
        // lands. Checking capacity and then writing is the race the file store
        // exists to close: concurrent writers all pass one cached measurement
        // before any of them has written a byte, and cross the reserve
        // together. A record is a fixed `POINTER_WIRE_LEN`, so that is the
        // whole charge.
        let reservation = match &self.chunks {
            Some(chunks) => match chunks.reserve(POINTER_WIRE_LEN as u64) {
                Ok(reservation) => Some(reservation),
                Err(e) => {
                    debug!("Rejecting pointer PUT for {}: {e}", hex::encode(address));
                    self.forget_clear(&state);
                    return PointerPutResponse::Error(ProtocolError::StorageFailed(e.to_string()));
                }
            },
            None => None,
        };
        // The charge travels with the write. Settling it here instead would
        // release it the moment this future is dropped, while the blocking
        // transaction it started runs on and publishes the file.
        let record_bytes = request.record.to_vec();
        let response = match self.store.commit(record, reservation).await {
            Ok(PutOutcome::Changed) => {
                // Offer it to the rest of the close group, proof included, so
                // every member holds it whichever of them the client reached.
                let writes = self.fresh_writes.read().clone();
                if let (Some(writes), Some(proof)) = (writes, request.payment_proof) {
                    if writes
                        .send(PointerFreshWrite {
                            record: record_bytes,
                            payment_proof: proof,
                        })
                        .is_err()
                    {
                        debug!(
                            "Replication is not running; pointer {} is not offered on",
                            hex::encode(address)
                        );
                    }
                }
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
        };
        // A look that cleared a final state is reused briefly for replays of
        // it; a write that did not land must not leave that answer behind.
        if !matches!(
            response,
            PointerPutResponse::Success { .. } | PointerPutResponse::Unchanged { .. }
        ) {
            self.forget_clear(&state);
        }
        response
    }

    /// Forget a clear look for `state`, if a witness took one.
    fn forget_clear(&self, state: &PointerState) {
        if state.is_terminal() {
            if let Some(witness) = self.final_witness.read().as_ref() {
                witness.forget_clear(state);
            }
        }
    }

    /// Everything that must hold before a record is worth verifying.
    ///
    /// `Some(response)` means refuse. Ordered cheapest first, and all of it
    /// ahead of the signature check, so a forged record for an address this
    /// node does not serve buys no cryptography.
    async fn admit(&self, state: &PointerState) -> Option<PointerPutResponse> {
        let address = state.address;

        // Any state the merge rule prefers to what this node knows, whatever
        // its counter: a node that missed updates, or joined the group after
        // them, must take the next one or it never catches up. An arrival that
        // loses to what is held was already answered as stale; this also
        // covers a record the node lost, which that comparison cannot see, so
        // a replay cannot roll it back.
        if !self.store.admits(state) {
            info!(
                "Rejecting pointer PUT for {}: counter {} does not beat the state this node knows",
                hex::encode(address),
                state.counter
            );
            return Some(PointerPutResponse::Stale {
                address,
                state_id: self.store.state_id(&address).unwrap_or_default(),
            });
        }

        if let Some(chunks) = &self.chunks {
            // A chunk already here means the two kinds collided. Refuse rather
            // than pick: whichever we chose, someone's data would vanish.
            if let Some(refusal) = cross_kind_refusal(address, chunks.exists(&address)) {
                return Some(refusal);
            }
            // Capacity before payment, as the chunk path does, and for the
            // size a record actually is rather than for nothing. The binding
            // charge is taken at the commit; this only avoids paying to find
            // out the disk is full.
            if let Err(e) = chunks.check_capacity_for(POINTER_WIRE_LEN as u64) {
                let addr = hex::encode(address);
                info!(
                    target: "ant_node::storage::disk_precheck",
                    addr = %addr,
                    kind = "pointer",
                    "Rejecting pointer PUT before payment verification: {e}"
                );
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

        // A final state an earlier check proved lost to another is refused
        // again here, before it buys a signature check or a round trip.
        if self.needs_final_check(state) {
            let proven = self
                .final_witness
                .read()
                .as_ref()
                .and_then(|witness| witness.proven_conflict(state));
            if let Some(conflict) = proven {
                return Some(PointerPutResponse::Stale {
                    address,
                    state_id: conflict.state_id,
                });
            }
        }
        None
    }

    /// Whether `state` needs the close group's word before this node takes
    /// it: it is final, and this node neither holds nor remembers a final
    /// state at its address.
    ///
    /// Nothing else is asked about. A lower counter can be replaced, so taking
    /// one blind costs nothing a later state cannot fix. A node that holds a
    /// final state has had its answer from the merge rule before this runs:
    /// the same state is unchanged and any other is stale. And a node that
    /// lost the file of a final state it held is admitted only that state
    /// again ([`PointerStore::admits`]), which restores what it already took
    /// rather than taking a new one. Asking there would let any peer on the
    /// other side of a fork keep it from restoring its own copy.
    fn needs_final_check(&self, state: &PointerState) -> bool {
        state.is_terminal()
            && !self
                .store
                .remembered(&state.address)
                .is_some_and(|known| known.is_terminal())
    }

    /// The answer to a paid final state the close group proves already lost,
    /// or that could not be checked in time; `None` to take it.
    async fn final_refusal(&self, state: &PointerState) -> Option<PointerPutResponse> {
        if !self.needs_final_check(state) {
            return None;
        }
        let witness = self.final_witness.read().as_ref().map(Arc::clone)?;
        match witness.check_final(state).await {
            FinalityCheck::Clear => None,
            // Named as the state the group proved, as for any stale arrival.
            FinalityCheck::Conflict(conflict) => {
                info!(
                    "Refusing final pointer state {} at {}: the close group already holds \
                     final state {}, so the owner has finalized it before",
                    hex::encode(state.state_id),
                    hex::encode(state.address),
                    hex::encode(conflict.state_id)
                );
                Some(PointerPutResponse::Stale {
                    address: state.address,
                    state_id: conflict.state_id,
                })
            }
            FinalityCheck::Busy => {
                debug!(
                    "Deferring final pointer state {} at {}: too many finality checks running",
                    hex::encode(state.state_id),
                    hex::encode(state.address)
                );
                Some(PointerPutResponse::Error(ProtocolError::Internal(
                    "too many finality checks running; try again".to_string(),
                )))
            }
        }
    }

    /// Handle a pointer GET.
    pub async fn handle_get(&self, request: PointerGetRequest) -> PointerGetResponse {
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
}

/// Decide whether a chunk already at `address` blocks this pointer.
///
/// Separated from the handler because the branch cannot be reached in a test
/// any other way: a pointer address comes out of BLAKE3's derive-key mode and a
/// chunk address out of a plain hash, so occupying both with real data would
/// take a collision across the two. The decision is what matters, so the
/// decision is what is tested.
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
    use crate::payment::{EvmVerifierConfig, PriceFloorConfig};
    use ant_protocol::pointer::{Pointer, PointerTarget, PointerTargetKind, FINAL_COUNTER};
    use saorsa_pqc::api::sig::{ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey};
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    /// A service whose chunk store guards a disk that cannot take another byte.
    async fn service_with_full_disk() -> (PointerService, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PointerStore::new(dir.path()).await.expect("store");
        let chunks = ChunkStore::new(crate::storage::ChunkStoreConfig {
            root_dir: dir.path().to_path_buf(),
            verify_on_read: false,
            max_map_size: 0,
            // Larger than any disk, so every capacity question answers "full".
            disk_reserve: u64::MAX,
            migration: crate::storage::MigrationConfig::default(),
        })
        .await
        .expect("chunk store");
        (
            PointerService::new(store).with_chunk_store(Arc::new(chunks)),
            dir,
        )
    }

    #[tokio::test]
    async fn a_full_disk_refuses_a_pointer_before_it_is_written() {
        // A disk with no room refuses at the admission check, before payment,
        // so a client is not charged to find out. This does not reach the
        // reservation — the store-level tests cover that — it covers the early
        // refusal and that nothing is stored when it fires.
        let (service, _dir) = service_with_full_disk().await;
        let record = signed(1, 0, 1);

        match service.handle_put(put(&record)).await {
            PointerPutResponse::Error(ProtocolError::StorageFailed(message)) => {
                assert!(
                    message.contains("disk space") || message.contains("reserve"),
                    "a full disk should say so, got: {message}"
                );
            }
            other => panic!("a full disk must refuse the write, got {other:?}"),
        }

        assert!(
            matches!(
                service
                    .handle_get(PointerGetRequest::new(record.address()))
                    .await,
                PointerGetResponse::NotFound { .. }
            ),
            "nothing may be stored when the disk had no room for it"
        );
    }

    #[tokio::test]
    async fn concurrent_creations_are_each_charged_against_the_disk() {
        // Every one of these would pass a bare capacity *check* against one
        // cached measurement. What stops them collectively crossing the
        // reserve is that each holds a charge until its write lands.
        let (service, dir) = service().await;
        let chunks = ChunkStore::new(crate::storage::ChunkStoreConfig {
            root_dir: dir.path().to_path_buf(),
            verify_on_read: false,
            max_map_size: 0,
            disk_reserve: 0,
            migration: crate::storage::MigrationConfig::default(),
        })
        .await
        .expect("chunk store");
        let service = service.with_chunk_store(Arc::new(chunks));

        let chunks = service.chunks.clone().expect("chunk store");
        let (written_before, in_flight_before) = chunks.capacity_counters();

        let mut writes = Vec::new();
        for seed in 1..=8u8 {
            let record = signed(seed, 0, 1);
            let service = service.clone();
            writes.push(tokio::spawn(async move {
                (record.address(), service.handle_put(put(&record)).await)
            }));
        }

        for write in writes {
            let (address, response) = write.await.expect("join");
            assert!(
                matches!(response, PointerPutResponse::Success { .. }),
                "a disk with room must take the write, got {response:?}"
            );
            assert!(matches!(
                service.handle_get(PointerGetRequest::new(address)).await,
                PointerGetResponse::Success { .. }
            ));
        }
        assert_eq!(service.store().len(), 8);

        // Each of the eight was charged, and none of the charges was left
        // hanging. Without the counters this would pass just as well against a
        // bare capacity check that charges nothing.
        // Exactly eight allocation charges. An inequality against the raw
        // record size would accept four: a record rounds up to the allocation
        // unit, and four of those already exceed eight record sizes.
        let one = ChunkStore::capacity_charge_for(POINTER_WIRE_LEN as u64);
        assert_eq!(
            chunks.capacity_counters(),
            (written_before + 8 * one, in_flight_before),
            "eight writes, eight charges, none left in flight"
        );
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
    async fn two_nodes_given_the_same_states_in_opposite_orders_agree() {
        // The convergence property, driven through the request handler rather
        // than the store. The gate in front of the merge rule is part of the
        // production path, and a gate that admits records by arrival order
        // would leave these two nodes holding different records for ever --
        // which is the fork the merge rule exists to prevent.
        let (first_node, _a) = service().await;
        let (second_node, _b) = service().await;

        // Two separately paid states at one counter. The merge rule says the
        // smaller target wins, whichever arrives first.
        let loser = signed(1, 0, 9);
        let winner = signed(1, 0, 1);
        assert!(winner.replaces(&loser));

        for record in [&loser, &winner] {
            first_node.handle_put(put(record)).await;
        }
        for record in [&winner, &loser] {
            second_node.handle_put(put(record)).await;
        }

        for (name, node) in [("first", &first_node), ("second", &second_node)] {
            match node
                .handle_get(PointerGetRequest::new(winner.address()))
                .await
            {
                PointerGetResponse::Success { record: bytes } => assert_eq!(
                    Pointer::from_bytes(&bytes).expect("parse").state_id(),
                    winner.state_id(),
                    "the {name} node kept the wrong record"
                ),
                other => panic!("expected the winner, got {other:?}"),
            }
        }

        // And the node that already had the winner refused to go back.
        assert!(matches!(
            second_node.handle_put(put(&loser)).await,
            PointerPutResponse::Stale { .. }
        ));
    }

    #[tokio::test]
    async fn a_fork_between_two_nodes_is_healed_by_any_later_counter() {
        // Two paid states at one counter, each reaching a different node: a
        // fork no read can settle for them. The next update, at any later
        // counter, lands on both and leaves them holding the same record.
        let (first_node, _a) = service().await;
        let (second_node, _b) = service().await;
        let one_side = signed(1, 1, 9);
        let other_side = signed(1, 1, 1);
        assert!(matches!(
            first_node.handle_put(put(&one_side)).await,
            PointerPutResponse::Success { .. }
        ));
        assert!(matches!(
            second_node.handle_put(put(&other_side)).await,
            PointerPutResponse::Success { .. }
        ));

        let healed = signed(1, 5, 4);
        for (name, node) in [("first", &first_node), ("second", &second_node)] {
            match node.handle_put(put(&healed)).await {
                PointerPutResponse::Success { address, state_id } => {
                    assert_eq!(address, healed.address());
                    assert_eq!(state_id, healed.state_id());
                }
                other => panic!("the {name} node refused the healing update: {other:?}"),
            }
            let held = node
                .store()
                .get(&healed.address())
                .await
                .expect("get")
                .expect("present");
            assert_eq!(held.state_id(), healed.state_id(), "the {name} node");
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
        let mut bytes = record.to_bytes();
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
            evm: EvmVerifierConfig::default(),
            cache_capacity: 16,
            close_group_size: ant_protocol::chunk::CLOSE_GROUP_SIZE,
            local_rewards_address: evmlib::common::Address::new([1u8; 20]),
            price_floor: PriceFloorConfig::default(),
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
    async fn any_counter_that_beats_what_is_held_is_taken() {
        let (service, _dir) = service().await;

        // A node that joined after the pointer was created holds nothing, so
        // the first record it sees need not be counter 0.
        let first_seen = signed(1, 5, 1);
        assert!(matches!(
            service.handle_put(put(&first_seen)).await,
            PointerPutResponse::Success { .. }
        ));

        // Anything older is stale, whatever else it says.
        for older in [0u64, 4] {
            assert!(
                matches!(
                    service.handle_put(put(&signed(1, older, 2))).await,
                    PointerPutResponse::Stale { .. }
                ),
                "counter {older} must not replace counter 5"
            );
        }

        // Anything newer lands, however far it skips.
        for newer in [6u64, 99, u64::MAX] {
            let record = signed(1, newer, 2);
            match service.handle_put(put(&record)).await {
                PointerPutResponse::Success { state_id, .. } => {
                    assert_eq!(state_id, record.state_id());
                }
                other => panic!("counter {newer} was refused: {other:?}"),
            }
        }
        let held = service
            .store()
            .get(&first_seen.address())
            .await
            .expect("get")
            .expect("present");
        assert_eq!(held.counter(), u64::MAX);
    }

    /// A close group whose answer to the finality question is fixed, and
    /// which counts how often it was asked.
    struct StubWitness {
        answer: FinalityCheck,
        proven: Option<PointerState>,
        asked: AtomicUsize,
        forgotten: AtomicUsize,
    }

    impl StubWitness {
        fn answering(answer: FinalityCheck) -> Arc<Self> {
            Arc::new(Self {
                answer,
                proven: None,
                asked: AtomicUsize::new(0),
                forgotten: AtomicUsize::new(0),
            })
        }

        /// One that already proved `conflict` in an earlier check.
        fn having_proven(conflict: PointerState) -> Arc<Self> {
            Arc::new(Self {
                answer: FinalityCheck::Clear,
                proven: Some(conflict),
                asked: AtomicUsize::new(0),
                forgotten: AtomicUsize::new(0),
            })
        }

        fn asked(&self) -> usize {
            self.asked.load(Ordering::SeqCst)
        }
    }

    impl FinalStateWitness for StubWitness {
        fn check_final<'a>(&'a self, _state: &'a PointerState) -> BoxFuture<'a, FinalityCheck> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            let answer = self.answer;
            Box::pin(async move { answer })
        }

        fn proven_conflict(&self, state: &PointerState) -> Option<PointerState> {
            self.proven
                .filter(|proven| proven.state_id != state.state_id)
        }

        fn forget_clear(&self, _state: &PointerState) {
            self.forgotten.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn final_state(seed: u8, target_byte: u8) -> Pointer {
        let (pk, sk) = keypair(seed);
        let target = PointerTarget::new(PointerTargetKind::Pointer, [target_byte; 32]);
        Pointer::sign(&sk, &pk, FINAL_COUNTER, target).expect("sign")
    }

    #[tokio::test]
    async fn a_final_state_the_group_proves_is_already_superseded_is_refused() {
        // The node has the pointer's ordinary state and has never seen a final
        // one, so the merge rule alone would take this. The group proves the
        // owner already finalized it elsewhere, so it is refused, named as the
        // state that got there first, and nothing is written.
        let (service, _dir) = service().await;
        let current = signed(1, 3, 1);
        service.handle_put(put(&current)).await;

        let established = final_state(1, 0xAA);
        let late = final_state(1, 0x01);
        let witness = StubWitness::answering(FinalityCheck::Conflict(established.state()));
        service.attach_final_state_witness(witness.clone());

        match service.handle_put(put(&late)).await {
            PointerPutResponse::Stale { address, state_id } => {
                assert_eq!(address, late.address());
                assert_eq!(
                    state_id,
                    established.state_id(),
                    "the first final state is named"
                );
            }
            other => panic!("a second final state must be refused, got {other:?}"),
        }
        assert_eq!(witness.asked(), 1);
        assert_eq!(
            service.store().state_id(&late.address()),
            Some(current.state_id()),
            "nothing was written"
        );
    }

    #[tokio::test]
    async fn a_final_state_nobody_contradicts_is_taken() {
        // Silence is not evidence: a group that proves nothing lets the final
        // state through on the merge rule.
        let (service, _dir) = service().await;
        let witness = StubWitness::answering(FinalityCheck::Clear);
        service.attach_final_state_witness(witness.clone());

        let transfer = final_state(2, 0x42);
        assert!(matches!(
            service.handle_put(put(&transfer)).await,
            PointerPutResponse::Success { .. }
        ));
        assert_eq!(witness.asked(), 1);
        assert_eq!(
            service.store().state_id(&transfer.address()),
            Some(transfer.state_id())
        );
    }

    #[tokio::test]
    async fn the_group_is_asked_only_about_a_final_state_the_node_lacks() {
        // A lower counter can always be replaced later, so it is taken without
        // a round trip. A node already holding a final state has its answer
        // from the merge rule before any round trip: the same state is
        // unchanged, and any other is stale.
        let (service, _dir) = service().await;
        let witness = StubWitness::answering(FinalityCheck::Clear);
        service.attach_final_state_witness(witness.clone());

        for counter in [0u64, 1, u64::MAX - 1] {
            assert!(matches!(
                service.handle_put(put(&signed(3, counter, 1))).await,
                PointerPutResponse::Success { .. }
            ));
        }
        assert_eq!(witness.asked(), 0, "no final state yet, no question");

        let first = final_state(3, 0x10);
        assert!(matches!(
            service.handle_put(put(&first)).await,
            PointerPutResponse::Success { .. }
        ));
        assert_eq!(witness.asked(), 1);

        let second = final_state(3, 0x01);
        match service.handle_put(put(&second)).await {
            PointerPutResponse::Stale { state_id, .. } => {
                assert_eq!(state_id, first.state_id());
            }
            other => panic!("a second final state must be stale, got {other:?}"),
        }
        assert!(matches!(
            service.handle_put(put(&final_state(3, 0x10))).await,
            PointerPutResponse::Unchanged { .. }
        ));
        assert_eq!(witness.asked(), 1, "a held final state answers for itself");
    }

    #[tokio::test]
    async fn a_node_restores_its_own_lost_final_state_without_asking() {
        // The node took a final state, then lost the file. The group holds
        // the other side of a fork, which a check would prove. Asking would
        // keep the node from restoring what it already took, for good; the
        // lost state itself is the one thing it is admitted, so nobody is
        // asked, and the rival is still refused.
        let (service, _dir) = service().await;
        let own = final_state(5, 0x10);
        let rival = final_state(5, 0x01);
        assert!(matches!(
            service.handle_put(put(&own)).await,
            PointerPutResponse::Success { .. }
        ));
        std::fs::remove_file(service.store().file_for(&own.address())).expect("remove");
        assert!(service
            .store()
            .get(&own.address())
            .await
            .expect("get")
            .is_none());

        let witness = StubWitness::answering(FinalityCheck::Conflict(rival.state()));
        service.attach_final_state_witness(witness.clone());
        assert!(matches!(
            service.handle_put(put(&own)).await,
            PointerPutResponse::Success { .. }
        ));
        assert_eq!(witness.asked(), 0, "restoring its own state asks nobody");
        assert_eq!(
            service.store().state_id(&own.address()),
            Some(own.state_id())
        );
        assert!(matches!(
            service.handle_put(put(&rival)).await,
            PointerPutResponse::Stale { .. }
        ));
    }

    /// A group that answers clear while, meanwhile, a rival final state
    /// lands on this node: the race a clear look can lose.
    struct RacingWitness {
        store: PointerStore,
        rival: Pointer,
        forgotten: AtomicUsize,
    }

    impl FinalStateWitness for RacingWitness {
        fn check_final<'a>(&'a self, _state: &'a PointerState) -> BoxFuture<'a, FinalityCheck> {
            Box::pin(async move {
                self.store
                    .put_bytes(&self.rival.to_bytes())
                    .await
                    .expect("the rival lands");
                FinalityCheck::Clear
            })
        }

        fn proven_conflict(&self, _state: &PointerState) -> Option<PointerState> {
            None
        }

        fn forget_clear(&self, _state: &PointerState) {
            self.forgotten.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn a_cleared_final_state_whose_write_fails_is_looked_for_again() {
        // The look found nothing, but a rival final state landed while it
        // looked, so the write it cleared comes back stale. The clear answer
        // must not outlive that write: a retry has to look again.
        let (landing, _other) = service().await;
        let (service, _dir) = service().await;
        let witness = Arc::new(RacingWitness {
            store: service.store().clone(),
            rival: final_state(8, 0x01),
            forgotten: AtomicUsize::new(0),
        });
        service.attach_final_state_witness(witness.clone());
        assert!(matches!(
            service.handle_put(put(&final_state(8, 0x42))).await,
            PointerPutResponse::Stale { .. }
        ));
        assert_eq!(witness.forgotten.load(Ordering::SeqCst), 1);

        // A write that lands keeps its answer.
        let witness = StubWitness::answering(FinalityCheck::Clear);
        landing.attach_final_state_witness(witness.clone());
        assert!(matches!(
            landing.handle_put(put(&final_state(9, 0x42))).await,
            PointerPutResponse::Success { .. }
        ));
        assert_eq!(witness.forgotten.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_busy_check_neither_takes_nor_refuses_a_final_state_for_good() {
        let (service, _dir) = service().await;
        let current = signed(6, 3, 1);
        service.handle_put(put(&current)).await;
        let witness = StubWitness::answering(FinalityCheck::Busy);
        service.attach_final_state_witness(witness.clone());

        let transfer = final_state(6, 0x42);
        assert!(matches!(
            service.handle_put(put(&transfer)).await,
            PointerPutResponse::Error(ProtocolError::Internal(_))
        ));
        assert_eq!(witness.asked(), 1);
        assert_eq!(
            service.store().state_id(&transfer.address()),
            Some(current.state_id()),
            "nothing was written"
        );
        assert!(
            service.store().admits(&transfer.state()),
            "and the state can still be taken later"
        );
    }

    #[tokio::test]
    async fn a_proven_conflict_is_refused_again_before_any_signature_check() {
        // Replaying a paid final state that already lost costs a node
        // nothing: the refusal comes from what an earlier check proved, ahead
        // of the signature check and without asking the group. A record
        // whose signature does not even verify shows the order.
        let (unwitnessed, _other) = service().await;
        let (service, _dir) = service().await;
        let established = final_state(7, 0xAA);
        let late = final_state(7, 0x01);
        let witness = StubWitness::having_proven(established.state());
        service.attach_final_state_witness(witness.clone());

        let mut forged = late.to_bytes();
        if let Some(last) = forged.last_mut() {
            *last ^= 0xFF;
        }
        match service
            .handle_put(PointerPutRequest::new(Bytes::from(forged.clone())))
            .await
        {
            PointerPutResponse::Stale { state_id, .. } => {
                assert_eq!(state_id, established.state_id());
            }
            other => panic!("a proven loser must be refused as stale, got {other:?}"),
        }
        assert_eq!(witness.asked(), 0, "and nobody is asked again");
        assert!(
            matches!(
                unwitnessed
                    .handle_put(PointerPutRequest::new(Bytes::from(forged.clone())))
                    .await,
                PointerPutResponse::Error(_)
            ),
            "the record really does fail its signature check"
        );

        // The proven state itself is not refused by its own proof.
        assert!(matches!(
            service.handle_put(put(&established)).await,
            PointerPutResponse::Success { .. }
        ));
    }

    #[tokio::test]
    async fn two_final_states_raced_to_two_nodes_leave_each_on_its_first() {
        // The one fork ADR-0018 allows: the owner signs two final states and
        // sends one to each node before either has heard of the other. Each
        // keeps what it took first and refuses the other, whichever sorts
        // first. Nothing on a node can settle it; a reader decides by how many
        // of the group hold each side.
        let (first_node, _a) = service().await;
        let (second_node, _b) = service().await;
        let one = final_state(4, 0x09);
        let other = final_state(4, 0x01);

        assert!(matches!(
            first_node.handle_put(put(&one)).await,
            PointerPutResponse::Success { .. }
        ));
        assert!(matches!(
            second_node.handle_put(put(&other)).await,
            PointerPutResponse::Success { .. }
        ));
        assert!(matches!(
            first_node.handle_put(put(&other)).await,
            PointerPutResponse::Stale { .. }
        ));
        assert!(matches!(
            second_node.handle_put(put(&one)).await,
            PointerPutResponse::Stale { .. }
        ));
        assert_eq!(
            first_node.store().state_id(&one.address()),
            Some(one.state_id())
        );
        assert_eq!(
            second_node.store().state_id(&other.address()),
            Some(other.state_id())
        );
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
