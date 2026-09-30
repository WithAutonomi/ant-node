//! Pointer replication (ADR-0016).
//!
//! Pointers ride the same replication machinery chunks do — the same close
//! groups, the same neighbour-sync rounds and churn triggers, the same quorum,
//! pruning and possession rules — but not the chunk pipeline itself. That
//! pipeline assumes a record never changes and that its key is the hash of its
//! bytes. A pointer's address is stable while its state changes, and two honest
//! replicas may hold different valid signatures over one state. So a pointer is
//! replicated by *state*:
//!
//! - **Fresh.** A node that accepts a paid state from a client forwards the
//!   record, with the proof that paid for it, to the rest of the close group.
//!   Each receiver checks the signature, its own responsibility and the payment
//!   itself before storing it.
//! - **Repair.** Every neighbour-sync round pushes hints: the states the sender
//!   holds that the receiver should hold. A receiver that lacks a hinted state,
//!   or holds an older one, asks the close group which state each holds, adopts
//!   the best state a quorum of them hold exactly, and fetches it from one of
//!   them. The record verifies itself; the quorum stands in for the payment
//!   proof, as presence quorum does for a chunk.
//! - **Pruning.** A record this node has been out of range of for the
//!   hysteresis period is deleted — at once if the node is far outside the
//!   group, otherwise only once all but one of the current close group prove
//!   they hold that state or a newer one by returning a valid record.
//! - **Possession.** Some minutes after offering a fresh state, the node asks
//!   each close-group member for the record. A member that is still responsible
//!   and cannot produce that state or a newer one is penalised.
//!
//! Requests go only to peers that have sent a pointer message themselves (see
//! [`PointerReplication::is_capable`]). A peer built before pointers cannot
//! decode them, and saorsa-core counts an unanswered request against the peer
//! it was sent to; asking only capable peers keeps older peers out of it. Every
//! neighbour-sync round pushes hints, empty or not, so capability is learned
//! within a cycle.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ant_protocol::pointer::{Pointer, PointerState, POINTER_WIRE_LEN};
use futures::stream::{self, StreamExt};
use parking_lot::Mutex;
use rand::Rng;
use saorsa_core::identity::PeerId;
use saorsa_core::{P2PNode, TrustEvent};
use tokio::sync::{mpsc, RwLock, Semaphore};
use tokio::task::{spawn_blocking, JoinHandle};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::ant_protocol::XorName;
use crate::logging::{debug, info, warn};
use crate::payment::{
    PaymentVerifier, VerificationContext, MAX_PAYMENT_PROOF_SIZE_BYTES,
    MIN_PAYMENT_PROOF_SIZE_BYTES,
};
use crate::pointer::store::{Inspected, PointerStore};
use crate::replication::admission;
use crate::replication::commitment_state::ResponderCommitmentState;
use crate::replication::config::{
    storage_admission_width, ReplicationConfig, FRESH_REPLICATION_DELIVERY_MAX_RETRIES,
    REPLICATION_PROTOCOL_ID,
};
use crate::replication::protocol::{
    PointerFetchRequest, PointerFetchResponse, PointerFreshOffer, PointerHints,
    PointerStateRequest, PointerStateResponse, PointerStateSummary, ReplicationMessage,
    ReplicationMessageBody, MAX_POINTER_HINTS_PER_MESSAGE, MAX_POINTER_STATE_REQUEST_ADDRESSES,
};
use crate::replication::pruning::prune_proofs_needed;
use crate::storage::{CapacityVerdict, ChunkStore};

use super::REPLICATION_TRUST_WEIGHT;

/// Inbound fresh offers verified at once. An offer costs a signature check and
/// an on-chain payment lookup, so a flood is dropped rather than queued; one
/// that is dropped is repaired by the next neighbour-sync round.
const MAX_CONCURRENT_OFFERS: usize = 16;

/// Fetch and state requests served at once.
const MAX_CONCURRENT_SERVES: usize = 32;

/// Fetch and state requests admitted at once, served or waiting to be. Past
/// it a request is dropped at admission rather than queued, as a chunk fetch
/// is, so a flood costs a bounded number of tasks.
const MAX_SERVES_OUTSTANDING: usize = MAX_CONCURRENT_SERVES * 4;

/// Of those, how many one peer may have: twice the [`MAX_REQUESTS_PER_PEER`]
/// an honest node lets itself have outstanding at any one peer, so its
/// requests are never dropped, even those arriving before the reply to the
/// last has released its place here, while one flooding peer cannot take the
/// room every other peer's requests need.
const MAX_SERVES_OUTSTANDING_PER_PEER: u32 = 16;

/// Pointer requests this node has outstanding at any one peer, across repair,
/// possession checks and pruning together. As many as a repair asks at once,
/// so repair is not slowed; the rest wait their turn rather than go out and
/// be dropped by the peer's per-peer allowance, which would make an honest
/// peer look as though it had not answered.
const MAX_REQUESTS_PER_PEER: usize = VERIFICATION_CONCURRENCY;

// An honest node's requests to one peer, repair included, never exceed what
// that peer admits from it, with room for a reply still releasing its place.
const _: () = assert!(
    MAX_SERVES_OUTSTANDING_PER_PEER as usize >= 2 * MAX_REQUESTS_PER_PEER,
    "a peer's serve allowance must cover what an honest node asks of it"
);

/// Most peers remembered as speaking pointers. Only routed peers are, and a
/// routing table removal forgets one, so this only bounds what removals missed
/// (a lagging event stream) could leave behind. Capability forgotten this way
/// is learned again from the peer's next hint push.
const MAX_CAPABLE_PEERS: usize = 4096;

/// Most hint pushes answering peers' sync requests at once. Each scans every
/// pointer this node holds, so a peer's sync request that finds them all
/// running gets no hints this time, and the next sync round delivers them.
const MAX_CONCURRENT_SYNC_ANSWERS: usize = 8;

/// Most peers remembered as having been answered with hints. Only routing-table
/// peers are answered, so this only bounds what a lagging table could leave
/// behind; past it the peer answered longest ago is forgotten, never a new one
/// refused.
const MAX_ANSWERED_SYNC_PEERS: usize = 4096;

/// How often the pending hints are looked at.
const VERIFICATION_TICK: Duration = Duration::from_millis(500);

/// Most addresses awaiting verification at once, so a hint flood cannot grow
/// memory without bound. A hint dropped here comes back next round.
const MAX_PENDING: usize = 65_536;

/// Most addresses verified per tick.
const MAX_VERIFICATIONS_PER_TICK: usize = 256;

/// Verifications and fetches in flight at once within a tick.
const VERIFICATION_CONCURRENCY: usize = 8;

/// Undecided rounds an address gets before it is dropped. It comes back with
/// the next hint.
const MAX_UNDECIDED_ROUNDS: u32 = 5;

/// Wait before retrying an undecided address, doubled each round.
const UNDECIDED_BACKOFF: Duration = Duration::from_secs(30);

/// Most prune candidates examined per pass.
const MAX_PRUNE_CANDIDATES_PER_PASS: usize = 256;

/// One peer's answer about one address: the state it holds there, if any.
type StateAnswer = ((PeerId, XorName), Option<PointerState>);

/// A pointer state this node accepted from a paying client, to be offered to
/// the rest of its close group.
pub struct PointerFreshWrite {
    /// The record, in its canonical encoding.
    pub record: Vec<u8>,
    /// The proof that paid for its state.
    pub payment_proof: Vec<u8>,
}

/// A state this node was told about and has not yet verified.
#[derive(Debug, Clone)]
struct Pending {
    /// The best state hinted so far.
    wanted: PointerState,
    /// Undecided rounds so far.
    attempts: u32,
    /// Not to be looked at again before this.
    not_before: Instant,
}

/// What a verification round decided for one address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// A quorum of the close group hold this state and it beats what is held
    /// here: fetch it from one of `holders`.
    Adopt {
        /// The state to fetch.
        state: PointerState,
        /// The peers that said they hold exactly it.
        holders: Vec<PeerId>,
    },
    /// Nothing reached quorum, but the peers that did not answer could still
    /// make one. Ask again later.
    Undecided,
    /// No state that beats what is held can reach quorum.
    Refused,
}

/// Decide what a round of answers supports.
///
/// `group_size` is the whole close group this node would ask, capable or not:
/// a peer that cannot be asked counts as unanswered, not as a vote. The quorum
/// is therefore the one a chunk would need, and a network where few peers
/// understand pointers yet cannot repair on the word of those few.
pub(crate) fn evaluate(
    held: Option<&PointerState>,
    group_size: usize,
    answers: &[(PeerId, Option<PointerState>)],
    quorum_needed: usize,
) -> Verdict {
    if group_size == 0 || quorum_needed == 0 {
        return Verdict::Undecided;
    }
    let mut by_state: Vec<(PointerState, Vec<PeerId>)> = Vec::new();
    for (peer, answer) in answers {
        let Some(state) = answer else { continue };
        match by_state
            .iter_mut()
            .find(|(known, _)| known.state_id == state.state_id)
        {
            Some((_, holders)) => holders.push(*peer),
            None => by_state.push((*state, vec![*peer])),
        }
    }
    let beats_held = |state: &PointerState| held.is_none_or(|held| state.replaces(held));

    let best = by_state
        .iter()
        .filter(|(state, holders)| holders.len() >= quorum_needed && beats_held(state))
        .fold(
            None::<&(PointerState, Vec<PeerId>)>,
            |best, candidate| match best {
                Some(current) if !candidate.0.replaces(&current.0) => Some(current),
                _ => Some(candidate),
            },
        );
    if let Some((state, holders)) = best {
        return Verdict::Adopt {
            state: *state,
            holders: holders.clone(),
        };
    }

    let unanswered = group_size.saturating_sub(answers.len());
    let largest = by_state
        .iter()
        .filter(|(state, _)| beats_held(state))
        .map(|(_, holders)| holders.len())
        .max()
        .unwrap_or(0);
    if largest.saturating_add(unanswered) >= quorum_needed {
        Verdict::Undecided
    } else {
        Verdict::Refused
    }
}

/// What asking a peer for a pointer record came to.
enum Fetched {
    /// A record that verifies and belongs at the address.
    Record(Pointer),
    /// A record that does not, which the peer has already been penalised for.
    Invalid,
    /// No record: no answer, an empty one, or one about another address.
    Nothing,
    /// A record this node could not check, for a reason of its own.
    LocalFailure,
}

/// What a possession check makes of one peer's answer about `fresh`.
#[derive(Debug, PartialEq, Eq)]
enum Possession {
    /// The peer served `fresh` or a state that replaces it.
    Holds,
    /// The peer could not produce `fresh` or anything newer.
    Missing,
    /// Nothing to judge the peer on: it served a record that does not verify,
    /// which the fetch has already charged it for, or this node could not
    /// check what it served.
    NotJudged,
}

/// Judge one peer's answer in a possession check for `fresh`.
fn judge_possession(fetched: Fetched, fresh: &PointerState) -> Possession {
    match fetched {
        Fetched::Record(record) => {
            let state = record.state();
            if state.state_id == fresh.state_id || state.replaces(fresh) {
                Possession::Holds
            } else {
                Possession::Missing
            }
        }
        Fetched::Nothing => Possession::Missing,
        Fetched::Invalid | Fetched::LocalFailure => Possession::NotJudged,
    }
}

/// Whether nothing but the map holds a peer's outbound permits.
///
/// Every holder, a request waiting for a permit or one holding it, has a
/// clone, and clones are only made under the map's lock. So an entry nothing
/// else holds can be dropped without a later request getting a second set of
/// permits beside one still in use, which would let this node exceed
/// [`MAX_REQUESTS_PER_PEER`] at that peer.
fn outbound_idle(permits: &Arc<Semaphore>) -> bool {
    Arc::strong_count(permits) == 1
}

/// How many members a repair counts its quorum over: the whole close group,
/// however few of them this node can see (ADR-0016). A member it cannot see is
/// unanswered, so a thin routing table leaves a repair undecided instead of
/// shrinking the quorum to what little it can see.
fn repair_width(seen: usize, close_group_size: usize) -> usize {
    seen.max(close_group_size)
}

/// Pointer replication for one node. See the module documentation.
pub struct PointerReplication {
    store: PointerStore,
    chunks: Arc<ChunkStore>,
    p2p: Arc<P2PNode>,
    payments: Arc<PaymentVerifier>,
    config: Arc<ReplicationConfig>,
    is_bootstrapping: Arc<RwLock<bool>>,
    /// Outbound record transfers, shared with chunk replication.
    send_semaphore: Arc<Semaphore>,
    offer_permits: Arc<Semaphore>,
    serve_permits: Arc<Semaphore>,
    /// Admission ahead of `serve_permits`: see [`MAX_SERVES_OUTSTANDING`].
    serve_admission: Arc<Semaphore>,
    /// Requests each peer has admitted and not yet had answered.
    serve_inflight: Arc<RwLock<HashMap<PeerId, u32>>>,
    /// This node's own requests outstanding at each peer (see
    /// [`MAX_REQUESTS_PER_PEER`]).
    outbound: Mutex<HashMap<PeerId, Arc<Semaphore>>>,
    /// Peers that have sent a pointer message: the only ones asked anything.
    capable: Mutex<HashSet<PeerId>>,
    /// Hinted states awaiting verification, by address.
    pending: Mutex<HashMap<XorName, Pending>>,
    /// When each held address was first seen continuously out of range.
    out_of_range: Mutex<HashMap<XorName, Instant>>,
    /// Hint pushes answering sync requests that may run at once.
    sync_answers: Arc<Semaphore>,
    /// When each peer was last answered with hints.
    answered_syncs: Mutex<AnsweredSyncs>,
    shutdown: CancellationToken,
    tracker: TaskTracker,
}

/// When each peer was last sent hints in answer to its own sync request.
#[derive(Default)]
struct AnsweredSyncs {
    at: HashMap<PeerId, Instant>,
}

impl AnsweredSyncs {
    /// Whether `peer` may be answered at `now`, and if so note it: not if it
    /// was answered less than `spacing` ago. A full map forgets the peers
    /// answered longest ago rather than refuse anyone new.
    fn admit(&mut self, peer: PeerId, now: Instant, spacing: Duration) -> bool {
        let recent = |at: &Instant| now.saturating_duration_since(*at) < spacing;
        if self.at.get(&peer).is_some_and(recent) {
            return false;
        }
        if self.at.len() >= MAX_ANSWERED_SYNC_PEERS && !self.at.contains_key(&peer) {
            self.at.retain(|_, at| recent(at));
        }
        if self.at.len() >= MAX_ANSWERED_SYNC_PEERS && !self.at.contains_key(&peer) {
            let oldest = self
                .at
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(peer, _)| *peer);
            if let Some(oldest) = oldest {
                self.at.remove(&oldest);
            }
        }
        self.at.insert(peer, now);
        true
    }
}

impl PointerReplication {
    /// Pointer replication over `store`, sharing the engine's resources.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        store: PointerStore,
        chunks: Arc<ChunkStore>,
        p2p: Arc<P2PNode>,
        payments: Arc<PaymentVerifier>,
        config: Arc<ReplicationConfig>,
        is_bootstrapping: Arc<RwLock<bool>>,
        send_semaphore: Arc<Semaphore>,
        shutdown: CancellationToken,
        tracker: TaskTracker,
    ) -> Self {
        Self {
            store,
            chunks,
            p2p,
            payments,
            config,
            is_bootstrapping,
            send_semaphore,
            offer_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_OFFERS)),
            serve_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_SERVES)),
            serve_admission: Arc::new(Semaphore::new(MAX_SERVES_OUTSTANDING)),
            serve_inflight: Arc::new(RwLock::new(HashMap::new())),
            outbound: Mutex::new(HashMap::new()),
            capable: Mutex::new(HashSet::new()),
            pending: Mutex::new(HashMap::new()),
            out_of_range: Mutex::new(HashMap::new()),
            sync_answers: Arc::new(Semaphore::new(MAX_CONCURRENT_SYNC_ANSWERS)),
            answered_syncs: Mutex::new(AnsweredSyncs::default()),
            shutdown,
            tracker,
        }
    }

    /// The pointer store this replication serves from.
    pub(crate) fn store(&self) -> &PointerStore {
        &self.store
    }

    // -----------------------------------------------------------------------
    // Capability
    // -----------------------------------------------------------------------

    /// Remember that `peer` speaks pointers, if it is in the routing table.
    ///
    /// Only a routed peer is remembered: it is the only kind this node ever
    /// asks, and the routing table's removals are what forget it again, so the
    /// set cannot outgrow the table however many identities send a message.
    async fn mark_capable(&self, peer: &PeerId) {
        if !self.p2p.dht_manager().is_in_routing_table(peer).await {
            return;
        }
        let mut capable = self.capable.lock();
        if capable.len() >= MAX_CAPABLE_PEERS && !capable.contains(peer) {
            if let Some(evicted) = capable.iter().next().copied() {
                capable.remove(&evicted);
            }
        }
        capable.insert(*peer);
    }

    /// Whether `peer` has sent a pointer message, and may therefore be asked.
    pub fn is_capable(&self, peer: &PeerId) -> bool {
        self.capable.lock().contains(peer)
    }

    /// Forget a peer that left the routing table.
    pub(crate) fn forget_peer(&self, peer: &PeerId) {
        self.capable.lock().remove(peer);
        let mut outbound = self.outbound.lock();
        if outbound.get(peer).is_some_and(outbound_idle) {
            outbound.remove(peer);
        }
    }

    /// The permits bounding this node's requests to `peer`.
    fn outbound_permits(&self, peer: &PeerId) -> Arc<Semaphore> {
        let mut outbound = self.outbound.lock();
        if outbound.len() >= MAX_CAPABLE_PEERS && !outbound.contains_key(peer) {
            // Peers nothing is outstanding at hold no state worth keeping.
            outbound.retain(|_, permits| !outbound_idle(permits));
        }
        Arc::clone(
            outbound
                .entry(*peer)
                .or_insert_with(|| Arc::new(Semaphore::new(MAX_REQUESTS_PER_PEER))),
        )
    }

    /// Addresses currently awaiting verification. Tests only.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.lock().len()
    }

    // -----------------------------------------------------------------------
    // Messaging
    // -----------------------------------------------------------------------

    async fn send_one_way(&self, peer: &PeerId, body: ReplicationMessageBody) -> bool {
        let msg = ReplicationMessage {
            request_id: rand::thread_rng().gen::<u64>(),
            body,
        };
        let Ok(bytes) = msg.encode() else {
            warn!("Failed to encode a pointer replication message");
            return false;
        };
        self.p2p
            .send_message(peer, REPLICATION_PROTOCOL_ID, bytes, &[])
            .await
            .is_ok()
    }

    async fn request(
        &self,
        peer: &PeerId,
        body: ReplicationMessageBody,
        timeout: Duration,
    ) -> Option<ReplicationMessageBody> {
        let _permit = self.outbound_permits(peer).acquire_owned().await.ok()?;
        let msg = ReplicationMessage {
            request_id: rand::thread_rng().gen::<u64>(),
            body,
        };
        let bytes = msg.encode().ok()?;
        let response = self
            .p2p
            .send_request(peer, REPLICATION_PROTOCOL_ID, bytes, timeout)
            .await
            .ok()?;
        ReplicationMessage::decode(&response.data)
            .ok()
            .map(|msg| msg.body)
    }

    async fn penalise(&self, peer: &PeerId) {
        self.p2p
            .report_trust_event(
                peer,
                TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
            )
            .await;
    }

    /// Ask `peer` for the record it holds at `address`, and check what comes
    /// back: a valid signature and the right address. Anything else counts
    /// against the peer.
    async fn fetch_record(&self, peer: &PeerId, address: &XorName) -> Option<Pointer> {
        match self.fetch_outcome(peer, address).await {
            Fetched::Record(record) => Some(record),
            Fetched::Invalid | Fetched::Nothing | Fetched::LocalFailure => None,
        }
    }

    /// [`Self::fetch_record`], saying whether a failure was a record that did
    /// not verify, which has already cost the peer, or no record at all.
    async fn fetch_outcome(&self, peer: &PeerId, address: &XorName) -> Fetched {
        let Some(body) = self
            .request(
                peer,
                ReplicationMessageBody::PointerFetchRequest(PointerFetchRequest {
                    address: *address,
                }),
                self.config.fetch_request_timeout,
            )
            .await
        else {
            return Fetched::Nothing;
        };
        let ReplicationMessageBody::PointerFetchResponse(response) = body else {
            return Fetched::Nothing;
        };
        if response.address != *address {
            return Fetched::Nothing;
        }
        let Some(bytes) = response.record else {
            return Fetched::Nothing;
        };
        // Parsing verifies the ML-DSA signature, milliseconds of CPU a peer
        // can demand once per record it serves: off the async executor, as
        // every other pointer signature check is (ADR-0016).
        let Ok(parsed) = spawn_blocking(move || Pointer::from_bytes(&bytes)).await else {
            // The check itself failed here, which says nothing about the peer.
            warn!(
                "Could not verify the pointer record {peer} served for {}",
                hex::encode(address)
            );
            return Fetched::LocalFailure;
        };
        match parsed {
            Ok(record) if record.address() == *address => Fetched::Record(record),
            Ok(_) | Err(_) => {
                debug!(
                    "Peer {peer} served an invalid pointer record for {}",
                    hex::encode(address)
                );
                self.penalise(peer).await;
                Fetched::Invalid
            }
        }
    }

    // -----------------------------------------------------------------------
    // Hints
    // -----------------------------------------------------------------------

    /// Push hints to `peers` in the background: for each, the states this
    /// node holds whose close group, in this node's view, includes that peer.
    ///
    /// Every peer gets at least one message, empty or not. That is how a peer
    /// learns this node understands pointers.
    pub(crate) fn push_hints_detached(self: &Arc<Self>, peers: Vec<PeerId>) {
        if peers.is_empty() {
            return;
        }
        let this = Arc::clone(self);
        self.tracker
            .spawn(async move { this.push_hints(&peers).await });
    }

    /// Answer a peer's sync request, admitted and still fresh, with this
    /// node's pointer hints, in the background: how a peer, including one
    /// still bootstrapping, learns the pointers it should hold.
    ///
    /// Each answer scans every pointer held, so only a routing-table peer is
    /// answered, at most once per shortest sync interval, which an honest
    /// peer never syncs faster than, and at most
    /// [`MAX_CONCURRENT_SYNC_ANSWERS`] answers run at once. A request that
    /// finds them all busy gets no hints this time; the next sync round sends
    /// them anyway.
    pub(crate) fn answer_sync_with_hints(self: &Arc<Self>, peer: PeerId) {
        let Ok(permit) = Arc::clone(&self.sync_answers).try_acquire_owned() else {
            debug!("Not answering {peer}'s sync with pointer hints: too many answers running");
            return;
        };
        let this = Arc::clone(self);
        self.tracker.spawn(async move {
            let _permit = permit;
            if !this.p2p.dht_manager().is_in_routing_table(&peer).await {
                return;
            }
            let admitted = this.answered_syncs.lock().admit(
                peer,
                Instant::now(),
                this.config.neighbor_sync_interval_min,
            );
            if admitted {
                this.push_hints(&[peer]).await;
            }
        });
    }

    /// Push hints to `peers` and wait until they are sent. This is what each
    /// neighbour-sync round runs in the background; tests call it to drive a
    /// round.
    pub async fn push_hints(&self, peers: &[PeerId]) {
        let self_id = *self.p2p.peer_id();
        let mut by_peer: HashMap<PeerId, Vec<PointerStateSummary>> =
            peers.iter().map(|peer| (*peer, Vec::new())).collect();
        for state in self.store.held_states() {
            if self.shutdown.is_cancelled() {
                return;
            }
            let group = self
                .p2p
                .dht_manager()
                .find_closest_nodes_local_with_self(&state.address, self.config.close_group_size)
                .await;
            for node in group {
                if node.peer_id == self_id {
                    continue;
                }
                if let Some(hints) = by_peer.get_mut(&node.peer_id) {
                    hints.push(state.into());
                }
            }
        }
        for (peer, hints) in by_peer {
            let batches: Vec<Vec<PointerStateSummary>> = if hints.is_empty() {
                vec![Vec::new()]
            } else {
                hints
                    .chunks(MAX_POINTER_HINTS_PER_MESSAGE)
                    .map(<[PointerStateSummary]>::to_vec)
                    .collect()
            };
            for hints in batches {
                self.send_one_way(
                    &peer,
                    ReplicationMessageBody::PointerHints(PointerHints { hints }),
                )
                .await;
            }
        }
    }

    /// Take in hints from `source`: queue each hinted state this node should
    /// hold and lacks, or holds an older state than.
    pub(crate) async fn handle_hints(&self, source: PeerId, hints: Vec<PointerStateSummary>) {
        self.mark_capable(&source).await;
        if hints.is_empty() {
            return;
        }
        // As for chunks: only a peer in our own routing table may tell us what
        // to hold.
        if !self.p2p.dht_manager().is_in_routing_table(&source).await {
            debug!("Dropping pointer hints from {source}: not in the routing table");
            return;
        }
        let self_id = *self.p2p.peer_id();
        let width = storage_admission_width(self.config.close_group_size);
        for summary in hints.into_iter().take(MAX_POINTER_HINTS_PER_MESSAGE) {
            let hinted = PointerState::from(summary);
            match self.store.state(&hinted.address) {
                Some(held) => {
                    if held.state_id == hinted.state_id || !hinted.replaces(&held) {
                        continue;
                    }
                }
                None => {
                    if !admission::is_responsible(&self_id, &hinted.address, &self.p2p, width).await
                    {
                        continue;
                    }
                }
            }
            self.enqueue(hinted);
        }
    }

    fn enqueue(&self, hinted: PointerState) {
        let mut pending = self.pending.lock();
        let len = pending.len();
        match pending.get_mut(&hinted.address) {
            Some(entry) => {
                if hinted.replaces(&entry.wanted) {
                    entry.wanted = hinted;
                    entry.attempts = 0;
                    entry.not_before = Instant::now();
                }
            }
            None if len < MAX_PENDING => {
                pending.insert(
                    hinted.address,
                    Pending {
                        wanted: hinted,
                        attempts: 0,
                        not_before: Instant::now(),
                    },
                );
            }
            None => {}
        }
    }

    // -----------------------------------------------------------------------
    // Verification and fetch
    // -----------------------------------------------------------------------

    /// Start the loop that verifies and fetches hinted states.
    pub(crate) fn start_verification_loop(self: &Arc<Self>) -> JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = this.shutdown.cancelled() => break,
                    () = tokio::time::sleep(VERIFICATION_TICK) => this.verify_due().await,
                }
            }
        })
    }

    /// Whether this node should look for anything to repair now.
    async fn may_repair(&self) -> bool {
        // As for chunks (ADR-0011): a node that cannot store what it would
        // fetch does not spend the network's time finding it. The hints wait,
        // and come back each round if they are dropped meanwhile.
        if self.chunks.capacity_verdict() == CapacityVerdict::Full {
            return false;
        }
        // A node still bootstrapping sees too little of its close group to
        // judge what a quorum of it holds. The hints wait for it.
        !*self.is_bootstrapping.read().await
    }

    /// Verify and fetch whatever is due now. Also the tests' way to drive it.
    pub async fn verify_due(&self) {
        if !self.may_repair().await {
            return;
        }
        let now = Instant::now();
        let due: Vec<(XorName, PointerState)> = self
            .pending
            .lock()
            .iter()
            .filter(|(_, entry)| entry.not_before <= now)
            .take(MAX_VERIFICATIONS_PER_TICK)
            .map(|(address, entry)| (*address, entry.wanted))
            .collect();
        if due.is_empty() {
            return;
        }

        let self_id = *self.p2p.peer_id();
        let mut groups: HashMap<XorName, Vec<PeerId>> = HashMap::new();
        let mut asked: HashMap<PeerId, Vec<XorName>> = HashMap::new();
        for (address, _) in &due {
            let group: Vec<PeerId> = self
                .p2p
                .dht_manager()
                .find_closest_nodes_local(address, self.config.close_group_size)
                .await
                .into_iter()
                .map(|node| node.peer_id)
                .filter(|peer| *peer != self_id)
                .collect();
            for peer in group.iter().filter(|peer| self.is_capable(peer)) {
                asked.entry(*peer).or_default().push(*address);
            }
            groups.insert(*address, group);
        }

        let answers = self.ask_states(asked).await;

        let decisions: Vec<(XorName, Verdict)> = due
            .iter()
            .map(|(address, _)| {
                let group = groups.get(address).map_or(&[][..], Vec::as_slice);
                let answered: Vec<(PeerId, Option<PointerState>)> = group
                    .iter()
                    .filter_map(|peer| {
                        answers
                            .get(&(*peer, *address))
                            .map(|answer| (*peer, *answer))
                    })
                    .collect();
                let held = self.store.state(address);
                // The quorum is counted over the whole close group, as
                // ADR-0016 has it: a member this node cannot see, because its
                // routing table is thin, counts as unanswered, never as a
                // smaller group. Otherwise one peer in a thin view could vote
                // alone for an owner-signed state nobody paid to store.
                let width = repair_width(group.len(), self.config.close_group_size);
                let verdict = evaluate(
                    held.as_ref(),
                    width,
                    &answered,
                    self.config.quorum_needed(width),
                );
                (*address, verdict)
            })
            .collect();

        let outcomes: Vec<(XorName, bool)> = stream::iter(decisions)
            .map(|(address, verdict)| async move {
                match verdict {
                    Verdict::Adopt { state, holders } => {
                        let stored = self.fetch_and_store(address, state, &holders).await;
                        (address, stored)
                    }
                    Verdict::Undecided => (address, false),
                    Verdict::Refused => {
                        info!(
                            "No quorum backs a newer state for pointer {}",
                            hex::encode(address)
                        );
                        self.pending.lock().remove(&address);
                        (address, true)
                    }
                }
            })
            .buffer_unordered(VERIFICATION_CONCURRENCY)
            .collect()
            .await;

        let now = Instant::now();
        let mut pending = self.pending.lock();
        for (address, settled) in outcomes {
            if settled {
                pending.remove(&address);
                continue;
            }
            if let Some(entry) = pending.get_mut(&address) {
                entry.attempts = entry.attempts.saturating_add(1);
                if entry.attempts >= MAX_UNDECIDED_ROUNDS {
                    pending.remove(&address);
                } else {
                    let backoff = UNDECIDED_BACKOFF
                        .saturating_mul(2u32.saturating_pow(entry.attempts.saturating_sub(1)));
                    entry.not_before = now + backoff;
                }
            }
        }
    }

    /// Ask each peer which state it holds at the addresses listed for it.
    async fn ask_states(
        &self,
        asked: HashMap<PeerId, Vec<XorName>>,
    ) -> HashMap<(PeerId, XorName), Option<PointerState>> {
        let requests: Vec<(PeerId, Vec<XorName>)> = asked
            .into_iter()
            .flat_map(|(peer, addresses)| {
                addresses
                    .chunks(MAX_POINTER_STATE_REQUEST_ADDRESSES)
                    .map(|chunk| (peer, chunk.to_vec()))
                    .collect::<Vec<_>>()
            })
            .collect();
        let replies: Vec<Vec<StateAnswer>> = stream::iter(requests)
            .map(|(peer, addresses)| async move {
                let body = self
                    .request(
                        &peer,
                        ReplicationMessageBody::PointerStateRequest(PointerStateRequest {
                            addresses: addresses.clone(),
                        }),
                        self.config.verification_request_timeout,
                    )
                    .await;
                let Some(ReplicationMessageBody::PointerStateResponse(response)) = body else {
                    return Vec::new();
                };
                addresses
                    .iter()
                    .zip(response.states)
                    .map(|(address, summary)| {
                        // An answer about a different address is no answer.
                        let state = summary
                            .filter(|summary| summary.address == *address)
                            .map(PointerState::from);
                        ((peer, *address), state)
                    })
                    .collect()
            })
            .buffer_unordered(VERIFICATION_CONCURRENCY)
            .collect()
            .await;
        replies.into_iter().flatten().collect()
    }

    /// Fetch `wanted` from one of `holders` and store it. Whether it is now
    /// held, or nothing further can come of this round.
    async fn fetch_and_store(
        &self,
        address: XorName,
        wanted: PointerState,
        holders: &[PeerId],
    ) -> bool {
        for holder in holders {
            let Some(record) = self.fetch_record(holder, &address).await else {
                continue;
            };
            // The quorum backed this state. A holder that has moved on since
            // serves a different one, which that quorum says nothing about.
            if record.state_id() != wanted.state_id {
                continue;
            }
            match self.store_verified(record, None).await {
                Ok(_) => return true,
                Err(e) => {
                    warn!(
                        "Could not store replicated pointer {}: {e}",
                        hex::encode(address)
                    );
                    return false;
                }
            }
        }
        false
    }

    /// Store a record whose signature has been checked, if it still belongs
    /// here and beats what is held.
    async fn store_verified(
        &self,
        record: Pointer,
        width: Option<usize>,
    ) -> crate::error::Result<bool> {
        let state = record.state();
        let self_id = *self.p2p.peer_id();
        let width = width.unwrap_or_else(|| storage_admission_width(self.config.close_group_size));
        let held = self.store.state(&state.address).is_some();
        if !held && !admission::is_responsible(&self_id, &state.address, &self.p2p, width).await {
            return Ok(false);
        }
        if !self.store.admits(&state) {
            return Ok(false);
        }
        let reservation = self.chunks.reserve(POINTER_WIRE_LEN as u64)?;
        self.store.commit(record, Some(reservation)).await?;
        Ok(true)
    }

    // -----------------------------------------------------------------------
    // Serving
    // -----------------------------------------------------------------------

    /// Admit a fetch or state request from `source`, or drop it.
    ///
    /// Admitted before a task exists, fairly across peers, as a chunk fetch
    /// is: each admitted request would otherwise be a task waiting on a serve
    /// permit with nothing bounding how many, and one peer could take every
    /// place.
    async fn admit_serve(&self, source: &PeerId, kind: &str) -> Option<super::ResponderGuard> {
        match super::admit_bounded_responder(
            &self.serve_admission,
            &self.serve_inflight,
            source,
            MAX_SERVES_OUTSTANDING,
            MAX_SERVES_OUTSTANDING_PER_PEER,
        )
        .await
        {
            Ok(guard) => Some(guard),
            Err(failure) => {
                debug!("Dropping a pointer {kind} request from {source}: {failure}");
                None
            }
        }
    }

    /// Answer a fetch request in the background.
    pub(crate) async fn serve_fetch_detached(
        self: &Arc<Self>,
        source: PeerId,
        request: PointerFetchRequest,
        request_id: u64,
        rr_message_id: Option<String>,
    ) {
        let Some(guard) = self.admit_serve(&source, "fetch").await else {
            return;
        };
        let this = Arc::clone(self);
        self.tracker.spawn(async move {
            let _guard = guard;
            let Ok(_permit) = this.serve_permits.acquire().await else {
                return;
            };
            this.mark_capable(&source).await;
            // `get` verifies the signature before serving, so a record damaged
            // on this disk is never handed on.
            let record = match this.store.get(&request.address).await {
                Ok(Some(record)) => Some(record.to_bytes()),
                Ok(None) | Err(_) => None,
            };
            super::send_replication_response(
                &source,
                &this.p2p,
                request_id,
                ReplicationMessageBody::PointerFetchResponse(PointerFetchResponse {
                    address: request.address,
                    record,
                }),
                rr_message_id.as_deref(),
            )
            .await;
        });
    }

    /// Answer a state request in the background, from the index.
    pub(crate) async fn serve_state_detached(
        self: &Arc<Self>,
        source: PeerId,
        request: PointerStateRequest,
        request_id: u64,
        rr_message_id: Option<String>,
    ) {
        // An honest peer never asks about more than this at once. The decoded
        // request would otherwise be held by its task for as long as it waits,
        // and the wire allows one far larger.
        if request.addresses.len() > MAX_POINTER_STATE_REQUEST_ADDRESSES {
            debug!(
                "Dropping a pointer state request from {source}: {} addresses",
                request.addresses.len()
            );
            return;
        }
        let Some(guard) = self.admit_serve(&source, "state").await else {
            return;
        };
        let this = Arc::clone(self);
        self.tracker.spawn(async move {
            let _guard = guard;
            let Ok(_permit) = this.serve_permits.acquire().await else {
                return;
            };
            this.mark_capable(&source).await;
            let states = request
                .addresses
                .iter()
                .take(MAX_POINTER_STATE_REQUEST_ADDRESSES)
                .map(|address| this.store.state(address).map(PointerStateSummary::from))
                .collect();
            super::send_replication_response(
                &source,
                &this.p2p,
                request_id,
                ReplicationMessageBody::PointerStateResponse(PointerStateResponse { states }),
                rr_message_id.as_deref(),
            )
            .await;
        });
    }

    // -----------------------------------------------------------------------
    // Fresh replication
    // -----------------------------------------------------------------------

    /// Start the loop that offers freshly paid states to their close groups.
    pub(crate) fn start_fresh_drainer(
        self: &Arc<Self>,
        mut writes: mpsc::UnboundedReceiver<PointerFreshWrite>,
    ) -> JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = this.shutdown.cancelled() => break,
                    write = writes.recv() => match write {
                        Some(write) => this.replicate_fresh(write).await,
                        None => break,
                    },
                }
            }
        })
    }

    /// Offer a freshly paid state to the rest of its close group, and schedule
    /// the check that they took it.
    pub async fn replicate_fresh(self: &Arc<Self>, write: PointerFreshWrite) {
        let Ok(state) = PointerState::parse(&write.record) else {
            warn!("A fresh pointer write did not parse; not replicating it");
            return;
        };
        let self_id = *self.p2p.peer_id();
        let targets: Vec<PeerId> = self
            .p2p
            .dht_manager()
            .find_closest_nodes_local_with_self(&state.address, self.config.close_group_size)
            .await
            .into_iter()
            .map(|node| node.peer_id)
            .filter(|peer| *peer != self_id)
            .collect();

        let msg = ReplicationMessage {
            request_id: rand::thread_rng().gen::<u64>(),
            body: ReplicationMessageBody::PointerFreshOffer(PointerFreshOffer {
                record: write.record,
                proof_of_payment: write.payment_proof,
            }),
        };
        let Ok(encoded) = msg.encode() else {
            warn!(
                "Failed to encode a fresh pointer offer for {}",
                hex::encode(state.address)
            );
            return;
        };
        let encoded = Arc::new(encoded);
        for peer in &targets {
            let p2p = Arc::clone(&self.p2p);
            let bytes = Arc::clone(&encoded);
            let semaphore = Arc::clone(&self.send_semaphore);
            let peer = *peer;
            self.tracker.spawn(async move {
                let Ok(_permit) = semaphore.acquire().await else {
                    return;
                };
                for attempt in 0..=FRESH_REPLICATION_DELIVERY_MAX_RETRIES {
                    match p2p
                        .send_message(&peer, REPLICATION_PROTOCOL_ID, bytes.as_ref().clone(), &[])
                        .await
                    {
                        Ok(()) => break,
                        Err(e) => debug!(
                            "Fresh pointer offer to {peer} failed (attempt {}): {e}",
                            attempt + 1
                        ),
                    }
                }
            });
        }
        debug!(
            "Fresh pointer {} offered to {} peers",
            hex::encode(state.address),
            targets.len()
        );
        self.schedule_possession_check(state, targets);
    }

    /// Take a fresh offer from `source` in the background, unless too many are
    /// already being verified.
    pub(crate) fn accept_offer_detached(
        self: &Arc<Self>,
        source: PeerId,
        offer: PointerFreshOffer,
    ) {
        let Ok(permit) = Arc::clone(&self.offer_permits).try_acquire_owned() else {
            info!("Dropping a fresh pointer offer from {source}: too many in flight");
            return;
        };
        let this = Arc::clone(self);
        self.tracker.spawn(async move {
            let _permit = permit;
            this.mark_capable(&source).await;
            this.accept_offer(source, offer).await;
        });
    }

    /// Verify and store a fresh offer. Cheapest checks first; the signature and
    /// the on-chain payment lookup only for a state that would change something
    /// here and that this node is responsible for.
    async fn accept_offer(&self, source: PeerId, offer: PointerFreshOffer) {
        if offer.record.len() != POINTER_WIRE_LEN
            || !(MIN_PAYMENT_PROOF_SIZE_BYTES..=MAX_PAYMENT_PROOF_SIZE_BYTES)
                .contains(&offer.proof_of_payment.len())
        {
            debug!("Dropping a malformed fresh pointer offer from {source}");
            self.penalise(&source).await;
            return;
        }
        let parsed = match self.store.inspect(&offer.record).await {
            Ok(Inspected::Candidate(parsed)) => parsed,
            Ok(Inspected::Unchanged(_) | Inspected::Stale(_)) => return,
            Err(e) => {
                debug!("Dropping an unparseable fresh pointer offer from {source}: {e}");
                self.penalise(&source).await;
                return;
            }
        };
        let state = *parsed.state();
        let self_id = *self.p2p.peer_id();
        // As for a chunk: a fresh offer is taken across the wider paid width.
        if !admission::is_responsible(
            &self_id,
            &state.address,
            &self.p2p,
            self.config.paid_list_close_group_size,
        )
        .await
        {
            return;
        }
        if !self.store.admits(&state)
            || self
                .chunks
                .check_capacity_for(POINTER_WIRE_LEN as u64)
                .is_err()
        {
            return;
        }
        let record = match self.store.verify(parsed).await {
            Ok(record) => record,
            Err(e) => {
                debug!("Fresh pointer offer from {source} does not verify: {e}");
                self.penalise(&source).await;
                return;
            }
        };
        if let Err(e) = self
            .payments
            .verify_pointer_payment_in(
                &state.address,
                &state.state_id,
                &offer.proof_of_payment,
                VerificationContext::FreshReplication,
            )
            .await
        {
            info!(
                "Fresh pointer offer for {} from {source} is not paid for: {e}",
                hex::encode(state.address)
            );
            return;
        }
        match self
            .store_verified(record, Some(self.config.paid_list_close_group_size))
            .await
        {
            Ok(true) => debug!(
                "Stored fresh pointer {} from {source}",
                hex::encode(state.address)
            ),
            Ok(false) => {}
            Err(e) => warn!(
                "Could not store fresh pointer {}: {e}",
                hex::encode(state.address)
            ),
        }
    }

    // -----------------------------------------------------------------------
    // Possession
    // -----------------------------------------------------------------------

    fn schedule_possession_check(self: &Arc<Self>, fresh: PointerState, peers: Vec<PeerId>) {
        if peers.is_empty() {
            return;
        }
        let min = self.config.possession_check_delay_min;
        let max = self.config.possession_check_delay_max.max(min);
        let delay = if max > min {
            rand::thread_rng().gen_range(min..=max)
        } else {
            min
        };
        let this = Arc::clone(self);
        self.tracker.spawn(async move {
            tokio::select! {
                () = this.shutdown.cancelled() => return,
                () = tokio::time::sleep(delay) => {}
            }
            this.check_possession(fresh, &peers).await;
        });
    }

    /// Ask each peer for the record, and penalise any still responsible for it
    /// that cannot produce `fresh` or a state that replaces it.
    pub async fn check_possession(&self, fresh: PointerState, peers: &[PeerId]) {
        let self_id = *self.p2p.peer_id();
        for peer in peers {
            // A peer that has left the group owes nothing, and one that cannot
            // be asked is never judged on its silence.
            if *peer == self_id || !self.owes(peer, &fresh.address).await {
                continue;
            }
            let fetched = self.fetch_outcome(peer, &fresh.address).await;
            if judge_possession(fetched, &fresh) != Possession::Missing {
                continue;
            }
            // Asking can wait on this peer's other requests and on the peers
            // before it, and it may have left the group meanwhile. It is
            // judged on what it owes now, not on what it owed when this began.
            if !self.owes(peer, &fresh.address).await {
                continue;
            }
            warn!(
                "Peer {peer} does not hold pointer {} it was offered",
                hex::encode(fresh.address)
            );
            self.penalise(peer).await;
        }
    }

    /// Whether `peer` is responsible for `address` in this node's view, and
    /// can be asked about it.
    async fn owes(&self, peer: &PeerId, address: &XorName) -> bool {
        self.is_capable(peer)
            && self
                .p2p
                .dht_manager()
                .find_closest_nodes_local_with_self(address, self.config.close_group_size)
                .await
                .iter()
                .any(|node| node.peer_id == *peer)
    }

    // -----------------------------------------------------------------------
    // Pruning
    // -----------------------------------------------------------------------

    /// Delete records this node has been out of range of for the hysteresis
    /// period, where that is safe. Run when a neighbour-sync cycle completes.
    ///
    /// `allow_remote` is false while bootstrapping: candidacy is still tracked,
    /// but nothing that needs other peers' proof is decided.
    ///
    /// A record a retained storage commitment still commits to is never
    /// deleted, exactly as for a chunk: an auditor pinning that commitment may
    /// still open it, and a node that deleted it would fail that audit.
    pub async fn prune_pass(
        &self,
        allow_remote: bool,
        commitment_state: Option<&ResponderCommitmentState>,
    ) {
        let committed = |address: &XorName| commitment_state.is_some_and(|cs| cs.is_held(address));
        let self_id = *self.p2p.peer_id();
        let retention = storage_admission_width(self.config.close_group_size);
        let now = Instant::now();
        let held = self.store.held_states();

        let mut candidates = Vec::new();
        for state in &held {
            if admission::is_responsible(&self_id, &state.address, &self.p2p, retention).await {
                self.out_of_range.lock().remove(&state.address);
                continue;
            }
            let first_seen = *self.out_of_range.lock().entry(state.address).or_insert(now);
            if now.duration_since(first_seen) >= self.config.prune_hysteresis_duration {
                candidates.push(*state);
            }
        }
        {
            let held: HashSet<XorName> = held.iter().map(|state| state.address).collect();
            self.out_of_range
                .lock()
                .retain(|address, _| held.contains(address));
        }

        let mut deleted = 0usize;
        for state in candidates.into_iter().take(MAX_PRUNE_CANDIDATES_PER_PASS) {
            if self.shutdown.is_cancelled() {
                return;
            }
            if committed(&state.address) {
                continue;
            }
            let wide = self
                .p2p
                .dht_manager()
                .find_closest_nodes_local_with_self(
                    &state.address,
                    self.config.paid_list_close_group_size,
                )
                .await;
            let far = wide.len() >= self.config.paid_list_close_group_size
                && !wide.iter().any(|node| node.peer_id == self_id);
            let confirmed = if far {
                true
            } else if allow_remote && !*self.is_bootstrapping.read().await {
                self.others_hold(&state).await
            } else {
                false
            };
            // Revalidate just before deleting: the group may have moved back.
            if confirmed
                && !committed(&state.address)
                && !admission::is_responsible(&self_id, &state.address, &self.p2p, retention).await
                && self.delete(&state.address).await
            {
                deleted += 1;
            }
        }
        if deleted > 0 {
            info!("Pruned {deleted} pointer records this node is no longer responsible for");
        }
    }

    /// Whether all but one of the current close group prove they hold `ours`
    /// or a newer state, by returning a valid record.
    async fn others_hold(&self, ours: &PointerState) -> bool {
        let group: Vec<PeerId> = self
            .p2p
            .dht_manager()
            .find_closest_nodes_local(&ours.address, self.config.close_group_size)
            .await
            .into_iter()
            .map(|node| node.peer_id)
            .collect();
        let needed = prune_proofs_needed(group.len());
        if needed == 0 {
            return false;
        }
        let mut proofs = 0usize;
        for peer in group.iter().filter(|peer| self.is_capable(peer)) {
            let proves = self
                .fetch_record(peer, &ours.address)
                .await
                .is_some_and(|record| {
                    let state = record.state();
                    state.state_id == ours.state_id || state.replaces(ours)
                });
            if proves {
                proofs += 1;
                if proofs >= needed {
                    return true;
                }
            }
        }
        false
    }

    async fn delete(&self, address: &XorName) -> bool {
        self.out_of_range.lock().remove(address);
        match self.store.delete(address).await {
            Ok(true) => {
                self.chunks.release(POINTER_WIRE_LEN as u64);
                true
            }
            Ok(false) => false,
            Err(e) => {
                warn!("Could not prune pointer {}: {e}", hex::encode(address));
                false
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ant_protocol::pointer::{PointerTarget, PointerTargetKind};
    use saorsa_pqc::api::sig::ml_dsa_65;

    fn state(counter: u64, target: u8, id: u8) -> PointerState {
        PointerState {
            state_id: [id; 32],
            address: [7; 32],
            counter,
            target: PointerTarget::new(PointerTargetKind::Chunk, [target; 32]),
        }
    }

    fn peer(byte: u8) -> PeerId {
        PeerId::from_bytes([byte; 32])
    }

    fn answers(list: &[(u8, Option<PointerState>)]) -> Vec<(PeerId, Option<PointerState>)> {
        list.iter().map(|(p, s)| (peer(*p), *s)).collect()
    }

    /// A peer's outbound permits are dropped only once nothing holds them, so
    /// a request in flight keeps the one set later requests share.
    fn record(counter: u64, target: u8) -> Pointer {
        let (pk, sk) = ml_dsa_65().generate_keypair_from_seed(&[3; 32]);
        let target = PointerTarget::new(PointerTargetKind::Chunk, [target; 32]);
        Pointer::sign(&sk, &pk, counter, target).expect("sign")
    }

    #[test]
    fn a_possession_check_judges_each_answer_once() {
        let fresh = record(5, 1);
        let judge = |fetched| judge_possession(fetched, &fresh.state());
        assert_eq!(judge(Fetched::Record(fresh.clone())), Possession::Holds);
        assert_eq!(
            judge(Fetched::Record(record(6, 9))),
            Possession::Holds,
            "a newer state is as good"
        );
        assert_eq!(judge(Fetched::Record(record(4, 1))), Possession::Missing);
        assert_eq!(judge(Fetched::Nothing), Possession::Missing);
        // The fetch already charged the peer for an invalid record; charging
        // it again as missing would count one bad answer twice.
        assert_eq!(judge(Fetched::Invalid), Possession::NotJudged);
        // A failure on this node says nothing about the peer.
        assert_eq!(judge(Fetched::LocalFailure), Possession::NotJudged);
    }

    #[test]
    fn a_peer_is_answered_with_hints_once_per_sync_interval() {
        let spacing = Duration::from_secs(600);
        let start = Instant::now();
        let mut answered = AnsweredSyncs::default();
        assert!(answered.admit(peer(1), start, spacing));
        assert!(
            !answered.admit(peer(1), start + Duration::from_secs(1), spacing),
            "a second request inside the interval gets no second scan"
        );
        assert!(
            answered.admit(peer(2), start, spacing),
            "other peers are not held up"
        );
        assert!(answered.admit(peer(1), start + spacing, spacing));

        // A full map forgets the peer answered longest ago; a new peer is
        // never refused for it.
        let mut full = AnsweredSyncs::default();
        let mut first = None;
        for i in 0..MAX_ANSWERED_SYNC_PEERS {
            let id = u32::try_from(i).expect("fits");
            let mut bytes = [0u8; 32];
            if let Some(prefix) = bytes.get_mut(..4) {
                prefix.copy_from_slice(&id.to_be_bytes());
            }
            let at = start + Duration::from_millis(u64::from(id));
            let each = PeerId::from_bytes(bytes);
            first.get_or_insert(each);
            assert!(full.admit(each, at, spacing));
        }
        let late = start + Duration::from_secs(10);
        assert!(
            full.admit(peer(0xEE), late, spacing),
            "a new peer is answered"
        );
        assert_eq!(full.at.len(), MAX_ANSWERED_SYNC_PEERS);
        let first = first.expect("one was admitted");
        assert!(!full.at.contains_key(&first), "the oldest was forgotten");
    }

    #[tokio::test]
    async fn outbound_permits_in_use_are_never_dropped() {
        let permits = Arc::new(Semaphore::new(MAX_REQUESTS_PER_PEER));
        assert!(outbound_idle(&permits));
        let held = Arc::clone(&permits)
            .acquire_owned()
            .await
            .expect("a permit");
        assert!(!outbound_idle(&permits), "a held permit keeps the set");
        drop(held);
        assert!(outbound_idle(&permits));
    }

    /// A node that sees one member of the close group, as one still filling
    /// its routing table does, cannot adopt a state on that member's word: the
    /// members it cannot see count as unanswered.
    #[test]
    fn a_thin_view_of_the_group_cannot_adopt_on_one_vote() {
        let config = ReplicationConfig::default();
        let unpaid = state(9, 1, 90);
        let width = repair_width(1, config.close_group_size);
        let got = evaluate(
            None,
            width,
            &answers(&[(1, Some(unpaid))]),
            config.quorum_needed(width),
        );
        assert!(
            matches!(got, Verdict::Undecided),
            "one visible peer must not decide, got {got:?}"
        );
        assert_eq!(
            repair_width(9, config.close_group_size),
            9,
            "a view wider than the configured group is counted as it is"
        );
    }

    #[test]
    fn a_state_a_quorum_holds_is_adopted_from_its_holders() {
        let newer = state(3, 1, 30);
        let got = evaluate(
            None,
            7,
            &answers(&[
                (1, Some(newer)),
                (2, Some(newer)),
                (3, Some(newer)),
                (4, Some(newer)),
                (5, None),
            ]),
            4,
        );
        match got {
            Verdict::Adopt { state, holders } => {
                assert_eq!(state.state_id, newer.state_id);
                assert_eq!(holders.len(), 4);
            }
            other => panic!("expected Adopt, got {other:?}"),
        }
    }

    #[test]
    fn a_state_below_quorum_is_never_adopted() {
        // One peer, or three, holding a state is not the network's word.
        let lone = state(9, 1, 90);
        let got = evaluate(
            None,
            7,
            &answers(&[
                (1, Some(lone)),
                (2, Some(lone)),
                (3, Some(lone)),
                (4, None),
                (5, None),
                (6, None),
                (7, None),
            ]),
            4,
        );
        assert_eq!(got, Verdict::Refused);

        // With one peer silent, three holders plus that peer could still make
        // four: undecided, not refused.
        let got = evaluate(
            None,
            7,
            &answers(&[
                (1, Some(lone)),
                (2, Some(lone)),
                (3, Some(lone)),
                (4, None),
                (5, None),
                (6, None),
            ]),
            4,
        );
        assert_eq!(got, Verdict::Undecided);
    }

    #[test]
    fn silence_is_not_a_vote_so_an_unanswered_group_stays_undecided() {
        let newer = state(3, 1, 30);
        let got = evaluate(None, 7, &answers(&[(1, Some(newer)), (2, Some(newer))]), 4);
        assert_eq!(got, Verdict::Undecided);
    }

    #[test]
    fn nothing_older_than_what_is_held_is_adopted() {
        let held = state(5, 1, 50);
        let older = state(4, 1, 40);
        let got = evaluate(
            Some(&held),
            7,
            &answers(&[
                (1, Some(older)),
                (2, Some(older)),
                (3, Some(older)),
                (4, Some(older)),
                (5, Some(older)),
            ]),
            4,
        );
        assert_eq!(got, Verdict::Refused);
    }

    #[test]
    fn of_two_states_with_quorum_the_merge_winner_is_adopted() {
        let lower = state(2, 9, 20);
        let winner = state(2, 1, 21);
        assert!(winner.replaces(&lower));
        let got = evaluate(
            None,
            8,
            &answers(&[
                (1, Some(lower)),
                (2, Some(lower)),
                (3, Some(lower)),
                (4, Some(lower)),
                (5, Some(winner)),
                (6, Some(winner)),
                (7, Some(winner)),
                (8, Some(winner)),
            ]),
            4,
        );
        match got {
            Verdict::Adopt { state, .. } => assert_eq!(state.state_id, winner.state_id),
            other => panic!("expected the winner, got {other:?}"),
        }
    }

    #[test]
    fn a_group_nobody_can_be_asked_in_is_undecided() {
        assert_eq!(evaluate(None, 0, &[], 0), Verdict::Undecided);
    }
}
