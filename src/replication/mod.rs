//! Replication subsystem for the Autonomi network.
//!
//! Implements Kademlia-style replication with:
//! - Fresh replication with `PoP` verification
//! - Neighbor sync with round-robin cycle management
//! - Batched quorum verification
//! - Storage audit protocol (anti-outsourcing)
//! - `PaidForList` persistence and convergence
//! - Responsibility pruning with hysteresis

// The replication engine intentionally holds `RwLock` read guards across await
// boundaries (e.g. reading sync_history while calling audit_tick). Clippy's
// nursery lint `significant_drop_tightening` flags these, but the guards must
// remain live for the duration of the call.
#![allow(clippy::significant_drop_tightening)]

pub mod admission;
pub mod audit;
pub mod bootstrap;
pub mod commitment;
pub mod commitment_state;
pub mod config;
pub mod fresh;
pub mod neighbor_sync;
pub mod paid_list;
pub mod possession;
pub mod protocol;
pub mod pruning;
pub mod quorum;
pub mod recent_provers;
pub mod scheduling;
pub mod slice;
pub mod storage_commitment_audit;
pub mod subtree;
pub mod types;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use lru::LruCache;
use std::pin::Pin;

use crate::logging::{debug, error, info, warn};
use futures::stream::FuturesUnordered;
use futures::{Future, StreamExt};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tokio::sync::{mpsc, Notify, RwLock, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::ant_protocol::XorName;
use crate::error::{Error, Result};
use crate::payment::{PaymentVerifier, VerificationContext};
use crate::replication::audit::AuditTickResult;
use crate::replication::commitment::{commitment_hash, StorageCommitment};
use crate::replication::commitment_state::{
    PeerCommitmentRecord, PersistedRetention, ResponderCommitmentState, GOSSIP_ANSWERABILITY_TTL,
};
use crate::replication::config::{
    max_parallel_fetch, storage_admission_width, ReplicationConfig, MAX_AUDIT_MESSAGE_SIZE,
    MAX_AUDIT_RESPONSES_PER_PEER, MAX_CONCURRENT_AUDIT_RESPONSES, MAX_CONCURRENT_REPLICATION_SENDS,
    MAX_CONCURRENT_SUBTREE_ROUND1, MAX_SUBTREE_ROUND1_PER_PEER, MAX_SUBTREE_SESSIONS,
    POSSESSION_AUDIT_PROTOCOL_ID, REPLICATION_PROTOCOL_ID, SUBTREE_AUDIT_PROTOCOL_ID,
    SUBTREE_ROUND1_WORK_BURST_BYTES, SUBTREE_ROUND1_WORK_REFILL_BYTES_PER_SEC, SUBTREE_SESSION_TTL,
};
use crate::replication::paid_list::PaidList;
use crate::replication::protocol::{
    FreshReplicationResponse, NeighborSyncResponse, ReplicationMessage, ReplicationMessageBody,
    VerificationResponse,
};
use crate::replication::quorum::KeyVerificationOutcome;
use crate::replication::recent_provers::RecentProvers;
use crate::replication::scheduling::ReplicationQueues;
use crate::replication::types::{
    AuditFailureReason, BootstrapClaimObservation, BootstrapState, FailureEvidence, HintPipeline,
    NeighborSyncState, PeerSyncRecord, RepairProofs, VerificationEntry, VerificationState,
};
use crate::storage::LmdbStorage;
use saorsa_core::identity::{NodeIdentity, PeerId};
use saorsa_core::{DhtNetworkEvent, P2PEvent, P2PNode, TrustEvent};
use saorsa_pqc::api::sig::{MlDsaSecretKey, MlDsaVariant};

/// Count of monetized-pin nominations DROPPED at the bounded ingress channel
/// because it was full (Amendment 2). Process-global because the producer is
/// the payment verifier (a different module) and the drop happens before the
/// per-drainer `received` counter. A non-zero value is the rollout signal that
/// nomination ingress is saturating — benign (penalty-free, lottery/next-
/// payment covered) but worth watching. `Closed` (engine shut down) is not
/// counted: it is not a saturation signal.
static FIRST_AUDIT_INGRESS_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Record one ingress-full drop. Called by the payment verifier's `try_send`
/// sites; read by the drainer's periodic summary.
pub(crate) fn note_monetized_ingress_drop() {
    FIRST_AUDIT_INGRESS_DROPPED.fetch_add(1, Ordering::Relaxed);
}

#[derive(Default)]
struct FirstAuditObservability {
    received: AtomicU64,
    queued: AtomicU64,
    coalesced: AtomicU64,
    duplicates: AtomicU64,
    capacity_evicted: AtomicU64,
    /// An event targeting the local peer itself, dropped at ingress: the node
    /// cannot network-audit itself (no dialable address for the local peer).
    self_target_skipped: AtomicU64,
    /// A strictly-lower-count same-peer nomination that was dropped so a
    /// higher-count pending pin survived. A sustained rise is the signal of an
    /// attempted "erase the inflated pin with a cheaper one" self-suppression.
    suppressed_lower: AtomicU64,
    cooldown_deferred_attempts: AtomicU64,
    rate_deferred_attempts: AtomicU64,
    window_deduped: AtomicU64,
    launched: AtomicU64,
    passed: AtomicU64,
    timed_out: AtomicU64,
    failed: AtomicU64,
    bootstrap_claims: AtomicU64,
    idle: AtomicU64,
    insufficient_keys: AtomicU64,
    outside_answerability_window: AtomicU64,
    inflight: AtomicU64,
}

/// Test-only snapshot of the first-audit scheduler counters.
///
/// Lets e2e tests assert on the scheduler's decisions (e.g. that a
/// self-targeting monetized pin was dropped and never launched) instead of
/// scraping log lines.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Debug, Clone, Copy)]
pub struct FirstAuditStats {
    /// Events ingested from the monetized-pin channel.
    pub received: u64,
    /// Events accepted into the pending first-audit queue.
    pub queued: u64,
    /// Events dropped because they targeted the local peer.
    pub self_target_skipped: u64,
    /// Audits launched.
    pub launched: u64,
    /// Launched audits that passed.
    pub passed: u64,
    /// Launched audits that timed out (non-response lane).
    pub timed_out: u64,
    /// Launched audits that ended in a confirmed failure.
    pub failed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirstAuditTerminalOutcome {
    Passed,
    Timeout,
    Failed,
    BootstrapClaim,
    Idle,
    InsufficientKeys,
}

impl FirstAuditTerminalOutcome {
    #[cfg(any(feature = "logging", test))]
    const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Timeout => "timeout",
            Self::Failed => "failed",
            Self::BootstrapClaim => "bootstrap_claim",
            Self::Idle => "idle",
            Self::InsufficientKeys => "insufficient_keys",
        }
    }
}

fn first_audit_terminal_outcome(result: &AuditTickResult) -> FirstAuditTerminalOutcome {
    match result {
        AuditTickResult::Passed { .. } => FirstAuditTerminalOutcome::Passed,
        AuditTickResult::Failed {
            evidence:
                FailureEvidence::AuditFailure {
                    reason: AuditFailureReason::Timeout,
                    ..
                },
        } => FirstAuditTerminalOutcome::Timeout,
        AuditTickResult::Failed { .. } => FirstAuditTerminalOutcome::Failed,
        AuditTickResult::BootstrapClaim { .. } => FirstAuditTerminalOutcome::BootstrapClaim,
        AuditTickResult::Idle => FirstAuditTerminalOutcome::Idle,
        AuditTickResult::InsufficientKeys => FirstAuditTerminalOutcome::InsufficientKeys,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirstAuditQueueOutcome {
    /// New peer inserted with free capacity.
    Queued,
    /// Collapsed with an existing same-peer entry; the incoming won (higher
    /// count, or equal count and newer) and replaced it.
    Coalesced,
    /// Collapsed with an existing same-peer entry; the incoming LOST because it
    /// had a STRICTLY LOWER count and was dropped, leaving the higher-count pin
    /// in place. This is the attempted cheaper-pin self-erasure signal.
    SuppressedLower,
    /// Collapsed with an existing same-peer entry of EQUAL count; the incoming
    /// lost the freshness tie (it was not the newer of the two) and the
    /// existing entry was retained. Benign, not an attack signal.
    RetainedOnTie,
    /// A DIFFERENT peer's entry was displaced from the capped pending queue
    /// (random victim) to make room.
    CapacityEvicted { peer: PeerId, pin: [u8; 32] },
}

/// Coalesce a monetized nomination into the per-peer pending queue with a
/// SECURITY-AWARE rule (ADR-0004 Amendment 2): keep the pin that most needs
/// auditing — the HIGHEST committed key count for that peer, newest on a tie.
///
/// A strictly-lower-count incoming must NOT displace a higher-count pending pin,
/// otherwise a peer can erase an inflated (audit-worthy) commitment by simply
/// monetizing a cheaper one right after — and a sidecar-only inflated pin has no
/// gossip-lottery backstop. When the incoming loses, the retained entry's LRU
/// recency is left UNTOUCHED (via `peek`), so a flood of low-count nominations
/// cannot promote the retained pin's lane position.
///
/// `incoming_is_newer` distinguishes ordinary enqueue (the incoming arrived
/// last, so it wins an equal-count tie for freshness) from a cooldown-race
/// requeue of an older reserved event (the pending successor is newer, so it
/// wins the tie).
fn coalesce_first_audit_event(
    pending: &mut LruCache<PeerId, MonetizedPinEvent>,
    incoming: MonetizedPinEvent,
    incoming_is_newer: bool,
    rng: &mut StdRng,
) -> FirstAuditQueueOutcome {
    if let Some(existing) = pending.peek(&incoming.peer) {
        // Strictly lower -> the incoming loses and is dropped WITHOUT touching
        // the retained pin's recency (the security-relevant self-erasure case).
        if incoming.key_count < existing.key_count {
            return FirstAuditQueueOutcome::SuppressedLower;
        }
        // Equal count -> keep the fresher; an older incoming loses a benign tie.
        if incoming.key_count == existing.key_count && !incoming_is_newer {
            return FirstAuditQueueOutcome::RetainedOnTie;
        }
        // Strictly higher, or equal-and-newer: the incoming wins. `push` updates
        // the value and bumps MRU; replacing an existing key never evicts a
        // different peer.
        let _ = pending.push(incoming.peer, incoming);
        return FirstAuditQueueOutcome::Coalesced;
    }
    // No same-peer entry. At capacity, displace a UNIFORMLY RANDOM incumbent,
    // never the LRU: deterministic keep-newest would let an ordered batch of
    // `cap` distinct-peer nominations flush a chosen target before any launch
    // lane sees it, cutting the eviction cost from probabilistic to exact. A
    // random victim caps an attacker's per-nomination eviction probability at
    // `1/cap` regardless of arrival order or timing, so suppressing a specific
    // target with confidence `1-e` costs ~`cap*ln(1/e)` distinct-peer paid
    // nominations and is never certain (ADR-0004 Amendment 4).
    if pending.len() >= pending.cap().get() {
        let victim = {
            let idx = rng.gen_range(0..pending.len());
            pending.iter().nth(idx).map(|(p, _)| *p)
        };
        if let Some(victim_peer) = victim {
            if let Some(evicted) = pending.pop(&victim_peer) {
                let _ = pending.push(incoming.peer, incoming);
                return FirstAuditQueueOutcome::CapacityEvicted {
                    peer: victim_peer,
                    pin: evicted.pin,
                };
            }
        }
    }
    match pending.push(incoming.peer, incoming) {
        None => FirstAuditQueueOutcome::Queued,
        // Unreachable: the random-displacement branch above guarantees
        // `len < cap` here (the caller holds `&mut`, so no concurrent insert
        // exists). Kept so any future logic error surfaces as an ACCOUNTED
        // eviction rather than silent loss — but note this arm would be
        // LRU-order, not random, so it must stay unreachable.
        Some((evicted_peer, evicted)) => FirstAuditQueueOutcome::CapacityEvicted {
            peer: evicted_peer,
            pin: evicted.pin,
        },
    }
}

/// ADR-0004 Amendment 2 (E′): slack added to the max launch jitter when
/// prefiltering a nomination's answerability at schedule time, covering the
/// spawn/dispatch latency between the timer firing and the wire challenge so a
/// jitter==MAX pin is not admitted only to fail the authoritative check by a
/// few milliseconds. Tiny against the multi-hour answerability window.
const FIRST_AUDIT_SEND_LATENCY_SLACK: Duration = Duration::from_secs(1);

/// A first audit the limiter recently launched at a peer: when, and the
/// committed key count that was audited (for the count-jump override).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecentFirstAudit {
    launched_at: Instant,
    key_count: u32,
}

/// Holds one first-audit in-flight slot; decrements the gauge on drop so a
/// panicking or cancelled audit task can never leak a slot and wedge the
/// [`config::FIRST_AUDIT_MAX_INFLIGHT`] cap shut.
struct FirstAuditInflightSlot(Arc<FirstAuditObservability>);

impl FirstAuditInflightSlot {
    fn acquire(observability: &Arc<FirstAuditObservability>) -> Self {
        observability.inflight.fetch_add(1, Ordering::Relaxed);
        Self(Arc::clone(observability))
    }
}

impl Drop for FirstAuditInflightSlot {
    fn drop(&mut self) {
        self.0.inflight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// ADR-0004 Amendment 2: whether `new_count` exceeds `audited_count` by more
/// than the [`config::FIRST_AUDIT_COUNT_JUMP_NUM`]/
/// [`config::FIRST_AUDIT_COUNT_JUMP_DEN`] ratio (`new > old * NUM / DEN`,
/// overflow-free integer math). A jump re-nominates a peer despite a recent
/// first audit: an inflated SIDECAR-ONLY pin is visible to payment verifiers
/// only, so no gossip-lottery audit can ever cover it.
const fn first_audit_count_jump(audited_count: u32, new_count: u32) -> bool {
    (new_count as u64) * config::FIRST_AUDIT_COUNT_JUMP_DEN
        > (audited_count as u64) * config::FIRST_AUDIT_COUNT_JUMP_NUM
}

/// The launch limiter's verdict for one pending monetized pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LimiterVerdict {
    /// Within budget and window: the caller may reserve a launch (and consumes
    /// a token via [`FirstAuditLimiter::reserve_token`] only if it does).
    Admit,
    /// Launch-rate budget or in-flight cap exhausted. Penalty-free: keep the
    /// pin pending and retry on a later tick.
    RateDeferred,
    /// The peer had a first audit within
    /// [`config::FIRST_AUDIT_PEER_REAUDIT_INTERVAL`] and the new pin's count
    /// shows no [`first_audit_count_jump`]. Drop the nomination (the
    /// gossip-lottery re-audit path is unaffected).
    WindowDeduped,
}

/// ADR-0004 Amendment 2: the first-audit launch limiter — a token bucket
/// (launch rate), an in-flight cap, and a per-peer re-audit window that
/// survives pin rotation.
///
/// This is the load-bearing aggregate bound the original scheduler lacked:
/// fleet-wide first-audit pressure becomes `nodes x refill-rate` instead of
/// `uploads x pinned-quotes-per-proof x verifying-storers`. Pure over passed
/// `now`/`inflight` values so every decision is unit-testable without a
/// runtime.
struct FirstAuditLimiter {
    /// Launch tokens available, at most [`config::FIRST_AUDIT_BUDGET_BURST`].
    tokens: u32,
    /// Refill anchor. While the bucket is full this tracks `now` (a full
    /// bucket accrues nothing); while below capacity it advances only by
    /// whole refill intervals so fractional elapsed time is never lost.
    last_refill: Instant,
    /// Peers given a first audit recently, with the audited key count.
    /// Bounded like the drainer's other per-peer maps.
    recent: LruCache<PeerId, RecentFirstAudit>,
}

impl FirstAuditLimiter {
    fn new(now: Instant) -> Self {
        Self {
            tokens: config::FIRST_AUDIT_BUDGET_BURST,
            last_refill: now,
            recent: LruCache::new(
                NonZeroUsize::new(MAX_LAST_COMMITMENT_BY_PEER).unwrap_or(NonZeroUsize::MIN),
            ),
        }
    }

    /// Whether the per-peer re-audit window admits a nomination for `peer`
    /// carrying `key_count` at `now`. Read-only (`peek`), so it is safe to
    /// call at ENQUEUE time — suppressed nominations never occupy pending
    /// slots — without disturbing LRU recency.
    fn window_allows(&self, peer: &PeerId, key_count: u32, now: Instant) -> bool {
        self.recent.peek(peer).map_or(true, |prev| {
            now.saturating_duration_since(prev.launched_at)
                >= config::FIRST_AUDIT_PEER_REAUDIT_INTERVAL
                || first_audit_count_jump(prev.key_count, key_count)
        })
    }

    /// Refill the token bucket for the time elapsed up to `now`.
    fn refill(&mut self, now: Instant) {
        if self.tokens >= config::FIRST_AUDIT_BUDGET_BURST {
            // Full bucket accrues nothing; keep the anchor current so the
            // next consumption starts its interval from here.
            self.last_refill = now;
            return;
        }
        let interval = config::FIRST_AUDIT_LAUNCH_INTERVAL;
        let elapsed = now.saturating_duration_since(self.last_refill);
        let earned = elapsed.as_nanos() / interval.as_nanos().max(1);
        if earned == 0 {
            return;
        }
        let capacity_gap = u128::from(config::FIRST_AUDIT_BUDGET_BURST - self.tokens);
        if earned >= capacity_gap {
            self.tokens = config::FIRST_AUDIT_BUDGET_BURST;
            self.last_refill = now;
        } else {
            // earned < capacity_gap <= u32::MAX, so both casts are lossless.
            self.tokens = self
                .tokens
                .saturating_add(u32::try_from(earned).unwrap_or(u32::MAX));
            let advance = interval.saturating_mul(u32::try_from(earned).unwrap_or(u32::MAX));
            self.last_refill = self.last_refill.checked_add(advance).unwrap_or(now);
        }
    }

    /// Decide whether a pending pin may launch now. Consumes NOTHING: the
    /// caller runs the remaining (per-peer cooldown) gate and calls
    /// [`Self::commit_launch`] only for a launch that actually happens, so a
    /// deferral elsewhere never burns budget or stamps the window.
    fn assess(
        &mut self,
        peer: &PeerId,
        key_count: u32,
        now: Instant,
        inflight: u64,
    ) -> LimiterVerdict {
        if !self.window_allows(peer, key_count, now) {
            return LimiterVerdict::WindowDeduped;
        }
        self.refill(now);
        if inflight >= config::FIRST_AUDIT_MAX_INFLIGHT || self.tokens == 0 {
            return LimiterVerdict::RateDeferred;
        }
        LimiterVerdict::Admit
    }

    /// Consume one launch token for a RESERVATION (ADR-0004 Amendment 2 E′).
    /// Does NOT stamp the per-peer window: the durable `recent` stamp happens
    /// only at [`Self::promote`], after the authoritative post-jitter
    /// answerability check, so a reservation that is later cancelled leaves no
    /// suppression behind.
    fn reserve_token(&mut self) {
        self.tokens = self.tokens.saturating_sub(1);
    }

    /// Return a token consumed by a reservation that was cancelled before it
    /// launched (answerability lapsed or a concurrent gossip audit won the
    /// cooldown). Capped at the burst so a spurious double-refund cannot exceed
    /// the bucket.
    fn refund_token(&mut self) {
        self.tokens = (self.tokens + 1).min(config::FIRST_AUDIT_BUDGET_BURST);
    }

    /// Stamp the per-peer re-audit window for a launch that is ACTUALLY firing
    /// (promotion). Separated from token consumption so suppression is only
    /// ever recorded for a real send.
    fn promote(&mut self, peer: PeerId, key_count: u32, now: Instant) {
        self.recent.put(
            peer,
            RecentFirstAudit {
                launched_at: now,
                key_count,
            },
        );
    }

    /// Test convenience: the pre-E′ atomic "a launch happened" — consume a token
    /// and stamp the window in one call. Production splits these across
    /// reservation and promotion; the limiter's own budget/window unit tests do
    /// not model the jitter reservation and use this shorthand.
    #[cfg(test)]
    fn commit_launch(&mut self, peer: PeerId, key_count: u32, now: Instant) {
        self.reserve_token();
        self.promote(peer, key_count, now);
    }
}

/// ADR-0004 Amendment 2 (E′ B-prefilter): whether a monetized pin is answerable
/// across the ENTIRE launch-jitter window ending at
/// `now + FIRST_AUDIT_LAUNCH_JITTER_MAX + slack`, so committing scheduling state
/// for it cannot later require aborting an out-of-window challenge. The
/// too-future bound is enforced at `now` (a jitter delay only ages a pin
/// forward, never toward the future); the too-old bound is enforced at the
/// latest possible send time. This is a conservative admission prefilter; the
/// authoritative answerability check still runs at promotion against the real
/// send-time wall clock, so A1 (no false conviction) holds regardless of how
/// jitter and the answerability margin are sized. `checked_add` overflow fails
/// closed (skip the pin).
fn quote_answerable_through_nominal_jitter(quote_ts: SystemTime, now: SystemTime) -> bool {
    let Some(latest_send) = now
        .checked_add(config::FIRST_AUDIT_LAUNCH_JITTER_MAX)
        .and_then(|t| t.checked_add(FIRST_AUDIT_SEND_LATENCY_SLACK))
    else {
        return false;
    };
    quote_within_audit_window(quote_ts, now) && quote_within_audit_window(quote_ts, latest_send)
}

/// Open the single first-audit reservation from `pending` if none is
/// outstanding: samples the launch jitter, snapshots the shared cooldown
/// read-only, and delegates to [`FirstAuditScheduler::try_reserve`]. One
/// shared implementation for both drainer call sites — the per-wake launch
/// phase and the pre-overflow opportunity inside the ingress batch — so the
/// two cannot drift.
async fn open_first_audit_reservation(
    scheduler: &mut FirstAuditScheduler,
    cooldown: &RwLock<HashMap<PeerId, Instant>>,
    observability: &Arc<FirstAuditObservability>,
) {
    if scheduler.has_reservation() {
        return;
    }
    let jitter = Duration::from_millis(rand::thread_rng().gen_range(
        0..=u64::try_from(config::FIRST_AUDIT_LAUNCH_JITTER_MAX.as_millis()).unwrap_or(u64::MAX),
    ));
    let inflight = observability.inflight.load(Ordering::Relaxed);
    let reserved = {
        let cooldown = cooldown.read().await;
        scheduler.try_reserve(Instant::now(), inflight, jitter, &cooldown, observability)
    };
    if reserved {
        if let Some(peer) = scheduler.reserved_peer() {
            debug!(
                "First-audit scheduler: audit_trigger=first_monetized outcome=reserved peer={peer} pending={}",
                scheduler.pending_len()
            );
        }
    }
}

/// A far-future `Instant` used to effectively DISABLE the promotion-timer
/// select arm when no reservation is outstanding. The drainer still wakes at
/// least every [`config::FIRST_AUDIT_RETRY_INTERVAL`] via its tick, so this only
/// needs to be comfortably past the next tick.
fn first_audit_far_future() -> Instant {
    Instant::now()
        .checked_add(Duration::from_secs(3600))
        .unwrap_or_else(Instant::now)
}

/// ADR-0004 Amendment 2 (E′): one outstanding first-audit reservation. Holds
/// its in-flight slot and launch token from schedule time until the jitter
/// timer fires; the durable suppression (`recent` + `first_audited`) is stamped
/// only if the authoritative post-jitter answerability + cooldown checks pass at
/// promotion, so a cancelled reservation leaves NO suppression behind.
struct FirstAuditReservation {
    event: MonetizedPinEvent,
    ready_at: Instant,
    inflight: FirstAuditInflightSlot,
}

/// ADR-0004 Amendment 2 (E′): the drainer-owned first-audit scheduler. Owns the
/// pending queue, the dedup set, the launch limiter, the alternating lane, and
/// the single outstanding reservation. All mutation is single-threaded in the
/// drainer task; the only asynchrony is the spawned audit I/O (which just holds
/// the moved-in in-flight slot). Kept as a struct so the reserve/promote/cancel
/// state machine is unit-testable with injected clocks.
struct FirstAuditScheduler {
    /// Pins already given a first audit (dedup). A pin enters only at PROMOTION
    /// (a real send), never at reservation, so a cancelled reservation can be
    /// re-nominated.
    first_audited: LruCache<[u8; 32], ()>,
    /// Highest-count-per-peer pending nominations not yet launched. Capped at
    /// [`FIRST_AUDIT_PENDING_CAP`] (what the token budget can launch within
    /// one effective answerability window); at capacity a uniformly RANDOM
    /// incumbent is displaced and counted as `capacity_evicted`, so eviction
    /// of a specific entry can never be forced deterministically. One further
    /// entry may be held in `reserved` outside this queue — a deliberate
    /// one-entry guard slot, so total schedulable occupancy is at most
    /// `cap + 1`; the summary line reports both (`pending`/`reserved`).
    pending: LruCache<PeerId, MonetizedPinEvent>,
    /// Token bucket + per-peer re-audit window.
    limiter: FirstAuditLimiter,
    /// The single outstanding reservation (E′ serializes reservations so the
    /// per-launch lane alternation is preserved and at most one jitter timer is
    /// live).
    reserved: Option<FirstAuditReservation>,
    /// Alternating launch lane, flipped on every PROMOTION (real launch).
    oldest_first_lane: bool,
    /// The local node's own peer ID. A verified payment's quote list includes
    /// the node's own quote, so the verifier emits a monetized-pin event for
    /// the local peer on every payment it verifies. The node cannot
    /// network-audit itself (there is no dialable address for the local peer,
    /// so the challenge fails instantly and is miscounted as a timeout), while
    /// any other payee that verifies the same payment schedules its own first
    /// audit of this node's pin — a self-dial adds no coverage either way.
    /// Such an event is dropped at ingress: never queued, and hence never
    /// launched nor marked first-audited.
    self_peer: PeerId,
    /// RNG for random-victim displacement (ADR-0004 Amendment 4). Owned by the
    /// scheduler so tests can seed it and reproduce eviction sequences exactly;
    /// production seeds from OS entropy at construction.
    rng: StdRng,
}

impl FirstAuditScheduler {
    fn new(now: Instant, self_peer: PeerId) -> Self {
        let dedup_cap = NonZeroUsize::new(MAX_LAST_COMMITMENT_BY_PEER).unwrap_or(NonZeroUsize::MIN);
        let pending_cap = NonZeroUsize::new(FIRST_AUDIT_PENDING_CAP).unwrap_or(NonZeroUsize::MIN);
        Self {
            first_audited: LruCache::new(dedup_cap),
            pending: LruCache::new(pending_cap),
            limiter: FirstAuditLimiter::new(now),
            reserved: None,
            oldest_first_lane: false,
            self_peer,
            rng: StdRng::from_entropy(),
        }
    }

    /// Observability getter: used by the scheduler summary log and unit tests,
    /// both absent from a release `--no-default-features` build, so it is dead
    /// only in that configuration.
    #[cfg_attr(not(feature = "logging"), allow(dead_code))]
    fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Observability getter (see [`Self::pending_len`]).
    #[cfg_attr(not(feature = "logging"), allow(dead_code))]
    fn tokens(&self) -> u32 {
        self.limiter.tokens
    }

    /// Observability getter (see [`Self::pending_len`]). Milliseconds since the
    /// signed quote timestamp of the oldest pin still awaiting a first audit:
    /// how close the longest-waiting pending pin is to aging out of the
    /// answerability window. A value climbing toward the window means pending
    /// work is expiring unaudited instead of launching; a small, steady value
    /// means the queue is draining promptly. Returns `0` when `pending` is empty
    /// and saturates to `0` for a future-dated quote (clock skew), never panics.
    #[cfg_attr(not(feature = "logging"), allow(dead_code))]
    fn oldest_pending_quote_age_ms(&self, now: SystemTime) -> u64 {
        self.pending
            .iter()
            .map(|(_, e)| e.quote_ts)
            .min()
            .and_then(|oldest| now.duration_since(oldest).ok())
            .map_or(0, |age| u64::try_from(age.as_millis()).unwrap_or(u64::MAX))
    }

    /// Drop every pending nomination that has aged past the answerability
    /// horizon. `try_reserve` collects expired entries only while it can scan —
    /// under token starvation it returns at the budget gate first — so without
    /// a periodic sweep dead entries squat the capped pending queue (displacing
    /// at capacity) and inflate the `pending`/`oldest_pending_quote_age_ms`
    /// telemetry. Each removal is accounted as `outside_answerability_window`,
    /// exactly like a scan-time expiry. Returns how many entries were dropped;
    /// survivor recency is untouched.
    fn sweep_expired(&mut self, wall_now: SystemTime, obs: &Arc<FirstAuditObservability>) -> usize {
        let expired: Vec<PeerId> = self
            .pending
            .iter()
            .filter(|(_, event)| !quote_answerable_through_nominal_jitter(event.quote_ts, wall_now))
            .map(|(peer, _)| *peer)
            .collect();
        for peer in &expired {
            self.pending.pop(peer);
        }
        if !expired.is_empty() {
            obs.outside_answerability_window.fetch_add(
                u64::try_from(expired.len()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
        expired.len()
    }

    fn has_reservation(&self) -> bool {
        self.reserved.is_some()
    }

    /// Whether admitting `event` would displace a DIFFERENT peer's pending
    /// entry: the queue is at capacity and `event.peer` has no incumbent to
    /// coalesce into. The drainer checks this before enqueueing so pending
    /// work gets a reservation opportunity BEFORE destructive overflow
    /// (ADR-0004 Amendment 4) — a successful reservation moves one entry out
    /// of `pending`, freeing the slot without any eviction.
    fn would_displace(&self, event: &MonetizedPinEvent) -> bool {
        self.pending.len() >= self.pending.cap().get() && self.pending.peek(&event.peer).is_none()
    }

    /// When the outstanding reservation becomes eligible for promotion.
    fn reserved_ready_at(&self) -> Option<Instant> {
        self.reserved.as_ref().map(|r| r.ready_at)
    }

    /// The peer of the outstanding reservation, if any.
    fn reserved_peer(&self) -> Option<PeerId> {
        self.reserved.as_ref().map(|r| r.event.peer)
    }

    /// Admit a monetized nomination into `pending`. Dropped at ingress if it
    /// targets the local peer (see [`Self::self_peer`]); dropped as a duplicate
    /// if already first-audited; the window screen is bypassed for the currently
    /// reserved peer (so a successor is retained across the reservation, never
    /// window-dropped); otherwise window-screened. Coalescing is
    /// highest-count-per-peer (newest on a tie) — a lower-count successor never
    /// displaces a higher-count pending pin. An incumbent that has aged past
    /// the answerability horizon is dropped (and accounted as an expiry) before
    /// coalescing, so a dead pin never vetoes a live nomination. Admission for
    /// a NEW peer at capacity displaces a uniformly RANDOM incumbent (see
    /// [`FIRST_AUDIT_PENDING_CAP`] and [`coalesce_first_audit_event`]):
    /// displacement is accounted as `capacity_evicted` and stamps no
    /// suppression, so a displaced peer's next nomination is judged like any
    /// newcomer. The drainer additionally offers a reservation opportunity
    /// via [`Self::would_displace`] before calling this on an overflowing
    /// arrival.
    fn enqueue(&mut self, event: MonetizedPinEvent, obs: &Arc<FirstAuditObservability>) {
        if event.peer == self.self_peer {
            obs.self_target_skipped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if self.first_audited.contains(&event.pin) {
            obs.duplicates.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let reserved_peer = self.reserved_peer();
        let is_reserved_peer = reserved_peer == Some(event.peer);
        if !is_reserved_peer
            && !self
                .limiter
                .window_allows(&event.peer, event.key_count, Instant::now())
        {
            obs.window_deduped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // A pending incumbent past the answerability horizon can never launch,
        // yet its (possibly higher) key count would still win the coalesce
        // against a live incoming — e.g. a fresh post-prune lower-count pin —
        // and under token starvation no reserve scan runs to collect it. Drop
        // it first so the incoming is judged on its own merits.
        let stale_incumbent = self.pending.peek(&event.peer).is_some_and(|existing| {
            !quote_answerable_through_nominal_jitter(existing.quote_ts, SystemTime::now())
        });
        if stale_incumbent {
            self.pending.pop(&event.peer);
            obs.outside_answerability_window
                .fetch_add(1, Ordering::Relaxed);
        }
        // Ordinary enqueue: the incoming arrived last, so it wins an equal-count
        // tie.
        match coalesce_first_audit_event(&mut self.pending, event, true, &mut self.rng) {
            FirstAuditQueueOutcome::Queued => {
                obs.queued.fetch_add(1, Ordering::Relaxed);
            }
            FirstAuditQueueOutcome::Coalesced | FirstAuditQueueOutcome::RetainedOnTie => {
                obs.coalesced.fetch_add(1, Ordering::Relaxed);
            }
            FirstAuditQueueOutcome::SuppressedLower => {
                obs.suppressed_lower.fetch_add(1, Ordering::Relaxed);
            }
            FirstAuditQueueOutcome::CapacityEvicted { .. } => {
                obs.queued.fetch_add(1, Ordering::Relaxed);
                obs.capacity_evicted.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Attempt to create the single reservation from `pending` (E′ reserve).
    /// Scans in the current lane order and reserves the FIRST eligible pin:
    /// consumes one token, acquires one in-flight slot, and sets `ready_at =
    /// mono_now + jitter`. Does NOT stamp `recent`/`first_audited` and does NOT
    /// flip the lane — those happen only at promotion. Returns whether a
    /// reservation was made. `cooldown` is a read-only snapshot (the
    /// authoritative check-and-stamp is at promotion).
    fn try_reserve(
        &mut self,
        mono_now: Instant,
        inflight: u64,
        jitter: Duration,
        cooldown: &HashMap<PeerId, Instant>,
        obs: &Arc<FirstAuditObservability>,
    ) -> bool {
        if self.reserved.is_some() || self.pending.is_empty() {
            return false;
        }
        self.limiter.refill(mono_now);
        if inflight >= config::FIRST_AUDIT_MAX_INFLIGHT || self.limiter.tokens == 0 {
            obs.rate_deferred_attempts.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        // MRU->LRU order; reverse for the oldest-first lane so the preferred
        // end is at the front.
        let mut ordered: Vec<(usize, PeerId, MonetizedPinEvent)> = self
            .pending
            .iter()
            .enumerate()
            .map(|(i, (p, e))| (i, *p, *e))
            .collect();
        self.pending.clear();
        if self.oldest_first_lane {
            ordered.reverse();
        }
        let mut chosen: Option<MonetizedPinEvent> = None;
        let mut kept: Vec<(usize, PeerId, MonetizedPinEvent)> = Vec::new();
        for (idx, peer, event) in ordered {
            if chosen.is_some() {
                kept.push((idx, peer, event));
                continue;
            }
            if self.first_audited.contains(&event.pin) {
                obs.duplicates.fetch_add(1, Ordering::Relaxed);
                continue; // drop: already audited
            }
            if !quote_answerable_through_nominal_jitter(event.quote_ts, SystemTime::now()) {
                obs.outside_answerability_window
                    .fetch_add(1, Ordering::Relaxed);
                continue; // drop: cannot stay answerable through the jitter
            }
            // Window + budget + inflight. Tokens do not decrease during the
            // scan (reserve happens after the loop) and `inflight` is fixed, so
            // after the upfront budget gate `assess` never returns RateDeferred
            // here; a defensive RateDeferred keeps the pin.
            match self
                .limiter
                .assess(&peer, event.key_count, mono_now, inflight)
            {
                LimiterVerdict::WindowDeduped => {
                    obs.window_deduped.fetch_add(1, Ordering::Relaxed);
                    continue; // drop: recently first-audited, no count jump
                }
                LimiterVerdict::RateDeferred => {
                    kept.push((idx, peer, event));
                    continue; // keep (defensive; unreachable after upfront gate)
                }
                LimiterVerdict::Admit => {}
            }
            if !cooldown_would_allow(cooldown, &peer, mono_now) {
                obs.cooldown_deferred_attempts
                    .fetch_add(1, Ordering::Relaxed);
                kept.push((idx, peer, event));
                continue; // keep: on shared cooldown, retry later
            }
            chosen = Some(event);
        }
        // Restore relative recency (oldest re-put first -> newest stays MRU).
        kept.sort_unstable_by_key(|(idx, _, _)| std::cmp::Reverse(*idx));
        for (_, peer, event) in kept {
            self.pending.put(peer, event);
        }
        let Some(event) = chosen else {
            return false;
        };
        self.limiter.reserve_token();
        let inflight_slot = FirstAuditInflightSlot::acquire(obs);
        let ready_at = mono_now.checked_add(jitter).unwrap_or(mono_now);
        self.reserved = Some(FirstAuditReservation {
            event,
            ready_at,
            inflight: inflight_slot,
        });
        true
    }

    /// Take the outstanding reservation if its jitter has elapsed at `mono_now`.
    fn take_due_reservation(&mut self, mono_now: Instant) -> Option<FirstAuditReservation> {
        if self
            .reserved
            .as_ref()
            .is_some_and(|r| mono_now >= r.ready_at)
        {
            self.reserved.take()
        } else {
            None
        }
    }

    /// Authoritative promotion of a due reservation (E′). The caller holds the
    /// shared cooldown write lock and passes the real send-time `wall_now` and
    /// `mono_now`. Returns `Some((event, slot))` to spawn the audit on a real
    /// launch, or `None` when the launch was cancelled (answerability lapsed
    /// during jitter) or requeued (a concurrent gossip audit won the cooldown).
    /// On both `None` paths the token is refunded, the in-flight slot released,
    /// and NO suppression is recorded.
    ///
    /// Known operational residual: suppression is stamped here, at promotion,
    /// while the wire challenge is sent by the detached task the caller spawns
    /// with the returned event. A task-start or encoding failure between the
    /// two therefore leaves a stamped-but-unsent window. No remote input can
    /// force that failure (it requires local task-spawn/alloc failure), so it
    /// is accepted rather than closed; closing it would require stamping from
    /// inside the spawned task and re-introduce the cancel-leaves-suppression
    /// race this design exists to prevent.
    fn resolve(
        &mut self,
        reservation: FirstAuditReservation,
        wall_now: SystemTime,
        mono_now: Instant,
        cooldown: &mut HashMap<PeerId, Instant>,
        obs: &Arc<FirstAuditObservability>,
    ) -> Option<(MonetizedPinEvent, FirstAuditInflightSlot)> {
        let FirstAuditReservation {
            event, inflight, ..
        } = reservation;
        // Authoritative answerability at the REAL send time.
        if !quote_within_audit_window(event.quote_ts, wall_now) {
            self.limiter.refund_token();
            obs.outside_answerability_window
                .fetch_add(1, Ordering::Relaxed);
            drop(inflight);
            return None; // cancelled; nothing stamped, nothing to roll back
        }
        // Authoritative shared-cooldown check-and-stamp. Losing this race to a
        // concurrent gossip audit requeues the reserved event through the SAME
        // security-aware coalescing: the reserved event is OLDER than any
        // same-peer successor (`incoming_is_newer = false`), so a higher-count
        // reserved event still wins over a lower-count successor (the inflated
        // pin must be audited), while an equal/higher successor is preserved.
        if !cooldown_allows_audit(cooldown, &event.peer, mono_now) {
            self.limiter.refund_token();
            obs.cooldown_deferred_attempts
                .fetch_add(1, Ordering::Relaxed);
            drop(inflight);
            // Account for the requeue outcome (the nomination itself was already
            // counted at ingress, so `queued` is not re-incremented): a capacity
            // eviction of a DIFFERENT peer and a suppressed reserved event are
            // both observable per the ADR funnel.
            match coalesce_first_audit_event(&mut self.pending, event, false, &mut self.rng) {
                FirstAuditQueueOutcome::CapacityEvicted { .. } => {
                    obs.capacity_evicted.fetch_add(1, Ordering::Relaxed);
                }
                FirstAuditQueueOutcome::SuppressedLower => {
                    obs.suppressed_lower.fetch_add(1, Ordering::Relaxed);
                }
                FirstAuditQueueOutcome::Queued
                | FirstAuditQueueOutcome::Coalesced
                | FirstAuditQueueOutcome::RetainedOnTie => {}
            }
            return None;
        }
        // Promote: stamp durable suppression, flip the lane, count the launch.
        self.limiter.promote(event.peer, event.key_count, mono_now);
        self.first_audited.put(event.pin, ());
        self.oldest_first_lane = !self.oldest_first_lane;
        obs.launched.fetch_add(1, Ordering::Relaxed);
        Some((event, inflight))
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Prefix used by saorsa-core's request-response mechanism.
const RR_PREFIX: &str = "/rr/";

/// Match an inbound topic against the replication protocol ids, in both the bare
/// gossip form and the `/rr/<id>` request-response form.
///
/// Returns the matched id (core [`REPLICATION_PROTOCOL_ID`],
/// [`SUBTREE_AUDIT_PROTOCOL_ID`] or [`POSSESSION_AUDIT_PROTOCOL_ID`]) and
/// whether it was the RR form. The matched id is carried into the handler so it
/// can enforce that each message family only arrives on its own id.
fn match_replication_protocol(topic: &str) -> Option<(&'static str, bool)> {
    for id in [
        REPLICATION_PROTOCOL_ID,
        SUBTREE_AUDIT_PROTOCOL_ID,
        POSSESSION_AUDIT_PROTOCOL_ID,
    ] {
        if topic == id {
            return Some((id, false));
        }
        if let Some(rest) = topic.strip_prefix(RR_PREFIX) {
            if rest == id {
                return Some((id, true));
            }
        }
    }
    None
}

/// Whether a decoded body belongs on the protocol id it arrived on:
/// subtree-audit bodies on [`SUBTREE_AUDIT_PROTOCOL_ID`], possession-audit
/// bodies on [`POSSESSION_AUDIT_PROTOCOL_ID`], every other body on
/// [`REPLICATION_PROTOCOL_ID`].
///
/// The receive guard drops any mismatch (a cross-version or misrouted message);
/// sharing this one predicate between the guard and its regression test means a
/// change to the rule cannot pass the test unnoticed.
fn body_matches_protocol(body: &ReplicationMessageBody, protocol: &str) -> bool {
    protocol == response_protocol_for(body)
}

/// The protocol id a body belongs on — the single source of truth for BOTH
/// directions: the receive guard ([`body_matches_protocol`]) and the outbound
/// response selector in `send_replication_response_checked`.
///
/// Sharing one function is what makes the family isolation symmetric. It also
/// removes a dependency on transport behaviour: saorsa-core correlates an RR
/// response by `(peer, msg_id)` rather than by protocol name, so a possession
/// `AuditResponse` sent on the core id would still reach an auditor waiting on
/// the possession id — but a bare (non-RR) response sent that way is dropped by
/// the peer's own guard, and correlation is a detail this layer should not rely
/// on.
fn response_protocol_for(body: &ReplicationMessageBody) -> &'static str {
    if body.is_subtree_audit() {
        SUBTREE_AUDIT_PROTOCOL_ID
    } else if body.is_possession_audit() {
        POSSESSION_AUDIT_PROTOCOL_ID
    } else {
        REPLICATION_PROTOCOL_ID
    }
}

fn fresh_offer_payment_context() -> VerificationContext {
    VerificationContext::FreshReplication
}

fn paid_notify_payment_context() -> VerificationContext {
    VerificationContext::PaidListAdmission
}

/// Boxed future type for in-flight fetch tasks.
type FetchFuture = Pin<Box<dyn Future<Output = (XorName, Option<FetchOutcome>)> + Send>>;

/// Shared dependencies for one verification worker cycle.
struct VerificationCycleContext<'a> {
    p2p_node: &'a Arc<P2PNode>,
    paid_list: &'a Arc<PaidList>,
    storage: &'a Arc<LmdbStorage>,
    queues: &'a Arc<RwLock<ReplicationQueues>>,
    config: &'a ReplicationConfig,
    bootstrap_state: &'a Arc<RwLock<BootstrapState>>,
    is_bootstrapping: &'a Arc<RwLock<bool>>,
    bootstrap_complete_notify: &'a Arc<Notify>,
    /// v12 §6 holder-eligibility inputs. The verifier downgrades a
    /// peer's Present claim to Unresolved unless they're a credited
    /// holder of the key (i.e. they recently passed a commitment-bound
    /// audit on it under their currently-credited commitment hash).
    last_commitment_by_peer: &'a Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>>,
    ever_capable_peers: &'a Arc<RwLock<HashSet<PeerId>>>,
    recent_provers: &'a Arc<RwLock<RecentProvers>>,
}

/// Fetch worker polling interval in milliseconds.
const FETCH_WORKER_POLL_MS: u64 = 100;

/// Verification worker polling interval in milliseconds.
const VERIFICATION_WORKER_POLL_MS: u64 = 250;

/// Verification cycle duration that is worth surfacing at info level.
const VERIFICATION_CYCLE_SLOW_LOG_MS: u128 = 500;

/// Standard trust event weight for per-operation success/failure signals.
///
/// Used for individual replication fetch outcomes, integrity check failures,
/// and bootstrap claim abuse. Distinct from `AUDIT_FAILURE_TRUST_WEIGHT` which
/// is reserved for confirmed audit failures.
const REPLICATION_TRUST_WEIGHT: f64 = 1.0;

/// Bootstrap drain check interval in seconds.
const BOOTSTRAP_DRAIN_CHECK_SECS: u64 = 5;

/// How often the responder rebuilds + rotates its storage commitment.
///
/// Each rebuild scans LMDB to compute leaf hashes; for ~10k keys this is
/// sub-100ms (BLAKE3 + tree build). Retention is gossip-anchored, NOT
/// rotation-anchored: the responder stays answerable for the current
/// commitment plus every root it recently gossiped that is still in-window
/// (~2 in steady state), each kept for `GOSSIP_ANSWERABILITY_TTL` (3 h) after
/// its last emission (see `commitment_state`). So the rotation cadence does
/// not by itself bound answerability — a gossiped commitment stays
/// answerable across rotations until its gossip TTL lapses.
///
/// Default: 1 hour, aligned with the worst-case neighbor-sync cooldown
/// (`NEIGHBOR_SYNC_COOLDOWN_SECS = 3600`). Because the gossip TTL (3 h)
/// comfortably exceeds the gap between our rotation and the next gossip
/// arrival at a remote peer, this prevents the "unknown commitment hash" ->
/// Idle audit-skip pattern from being the common case.
///
/// Why not faster: the v12 pin is bound to a specific point-in-time
/// commitment, so rotation isn't security-critical for pin freshness —
/// only for keeping the committed key set current as the responder
/// writes new keys. 1 hour is plenty for that, and slow enough that
/// honest auditors mostly hit `current` or `previous` rather than the
/// "rotated past" case.
const COMMITMENT_ROTATION_INTERVAL_SECS: u64 = 3600;

/// How often the responder retention snapshot is flushed to disk (ADR-0004 A1).
/// Short relative to the answerability TTL (3 h) so a gossip-stamp refresh is
/// durable well before it could matter to a restart, while the write-on-change
/// guard keeps idle nodes from needless disk writes.
const RETENTION_PERSIST_INTERVAL_SECS: u64 = 30;

/// Cadence of the `replication traffic summary (cumulative)` INFO lines
/// (V2-623). A `const` so testnets can drop it to 60s; 300s is the production
/// default that keeps log volume negligible.
const TRAFFIC_SUMMARY_INTERVAL_SECS: u64 = 300;

/// Maximum tolerated auditor↔responder wall-clock skew for the first-audit
/// in-window screen (ADR-0004 A1 guardrail A). The screen accepts a monetized pin
/// for first audit only if its SIGNED `quote_ts` lands in
/// `[now - (GOSSIP_ANSWERABILITY_TTL - MONETIZED_AUDIT_SKEW_MARGIN), now + MONETIZED_AUDIT_SKEW_MARGIN]`
/// — fail-closed on BOTH ends: a quote dated too far in the future (a
/// badly-skewed or replayed quote) and one too old (the responder may have aged
/// the pin out) are both skipped, so — with grace removed — a stale/skewed quote
/// cannot frame an honest node. This assumes bounded clock skew (nodes NTP-synced
/// within this margin); a legit first audit fires moments after payment
/// (`quote_ts ≈ now`), far from either bound. The gossip-lottery path (which pins
/// the responder's OWN freshly-gossiped root) is the clock-skew-immune backstop.
/// 30 min dwarfs any realistic honest skew while leaving a wide audit window.
const MONETIZED_AUDIT_SKEW_MARGIN: Duration = Duration::from_secs(30 * 60);

/// ADR-0004 A1 (guardrail A): whether a monetized pin's SIGNED `quote_ts` lands
/// inside the answerability window relative to `now`, so first-auditing it cannot
/// false-convict once grace is removed. Fail-closed on BOTH ends (see
/// [`MONETIZED_AUDIT_SKEW_MARGIN`]): a quote more than the skew margin in the
/// future, or older than `GOSSIP_ANSWERABILITY_TTL - margin`, is out of window.
/// All comparisons use `duration_since` (no `Duration` overflow).
fn quote_within_audit_window(quote_ts: SystemTime, now: SystemTime) -> bool {
    let too_future = quote_ts
        .duration_since(now)
        .is_ok_and(|ahead| ahead > MONETIZED_AUDIT_SKEW_MARGIN);
    let audit_cutoff = GOSSIP_ANSWERABILITY_TTL.saturating_sub(MONETIZED_AUDIT_SKEW_MARGIN);
    let too_old = now
        .duration_since(quote_ts)
        .is_ok_and(|age| age >= audit_cutoff);
    !(too_future || too_old)
}

/// Minimum interval between commitment signature verifications for a
/// single peer (v10/v12 §2 step 3 + §11 `DoS`).
///
/// A sybil that bypasses the routing-table gate (e.g. by transient
/// bucket pollution) could otherwise force one ML-DSA-65 verify (~1 ms)
/// per gossip message. This rate limit caps the verify-per-peer rate
/// at 1/min, which is comfortably above the legitimate gossip cadence
/// (the 10-20 min neighbor-sync round on each peer).
const COMMITMENT_SIG_VERIFY_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// Hard cap on the size of `last_commitment_by_peer`.
///
/// Bounds the per-process memory cost of the auditor's per-peer
/// commitment cache. Each entry holds a `StorageCommitment`
/// (~5 KiB: 1952-byte pubkey + 3293-byte signature + small fields).
/// At 4096 entries the cache is ~20 MiB, which comfortably covers a
/// realistic close-group neighborhood. When the cap is hit, one
/// arbitrary existing entry is evicted on insert (`HashMap` iteration
/// order is unspecified; we do not track insertion order). The
/// `PeerRemoved` handler proactively drops entries as the DHT
/// detects departures, and `ingest_peer_commitment` only admits
/// commitments from peers currently in the routing table — together
/// the cap is the third line of defence against sybil/churn flooding.
const MAX_LAST_COMMITMENT_BY_PEER: usize = 4096;

/// ADR-0004 Amendment 4: admission cap for the first-audit pending queue,
/// sized to the launch budget instead of the commitment cache.
///
/// The token bucket can launch at most one audit per
/// [`config::FIRST_AUDIT_LAUNCH_INTERVAL`] (plus the
/// [`config::FIRST_AUDIT_BUDGET_BURST`] allowance), and a pending pin stays
/// launchable for at most the effective answerability window
/// ([`GOSSIP_ANSWERABILITY_TTL`] − [`MONETIZED_AUDIT_SKEW_MARGIN`]). Any
/// occupancy beyond `window / interval + burst` is work that cannot launch
/// before it expires, so admitting it only builds an aging backlog whose
/// telemetry measures the backlog instead of schedulable work.
///
/// At capacity, admission displaces a uniformly RANDOM incumbent (counted as
/// `capacity_evicted`), so under overload `pending` degrades to a budget-sized
/// rolling sample in which no arrival order lets an attacker deterministically
/// flush a chosen target; a fresh pin always enters the sample with an
/// unpredictable chance of near-immediate audit, whereas refusing at the door
/// would let a sustained payment flood guarantee that every later pin is never
/// admitted. See [`coalesce_first_audit_event`] for the displacement rule and
/// ADR-0004 Amendment 4 for the eviction-cost math.
///
/// Derivation uses the STRICT reserve-time horizon: a launch at quote age `a`
/// is usable only if the quote stays answerable through `a` plus the maximum
/// launch jitter and send slack, so the last usable refill is the largest
/// `k` with `k * interval < cutoff - jitter_max - slack`. The unit test
/// simulates the shipped predicate instant-by-instant and must agree.
#[allow(clippy::cast_possible_truncation)] // bounded by TTL-secs/interval-secs + burst (~31)
const FIRST_AUDIT_PENDING_CAP: usize = {
    let strict_horizon_secs = GOSSIP_ANSWERABILITY_TTL
        .as_secs()
        .saturating_sub(MONETIZED_AUDIT_SKEW_MARGIN.as_secs())
        .saturating_sub(config::FIRST_AUDIT_LAUNCH_JITTER_MAX.as_secs())
        .saturating_sub(FIRST_AUDIT_SEND_LATENCY_SLACK.as_secs());
    // Strictly-inside count: a refill landing exactly ON the horizon is dead
    // (`age >= cutoff` rejects), hence the `- 1`. Compile-time division-by-zero
    // if the launch interval is ever zeroed: a zero interval makes the budget
    // (and this cap) meaningless.
    let refills =
        strict_horizon_secs.saturating_sub(1) / config::FIRST_AUDIT_LAUNCH_INTERVAL.as_secs();
    (refills + config::FIRST_AUDIT_BUDGET_BURST as u64) as usize
};

// Compile-time guardrails: the cap must be a usable `LruCache` capacity and
// strictly tighter than the commitment-cache bound it replaced.
const _: () = {
    assert!(FIRST_AUDIT_PENDING_CAP >= 1);
    assert!(FIRST_AUDIT_PENDING_CAP < MAX_LAST_COMMITMENT_BY_PEER);
};

/// Cap on the sticky `ever_capable_peers` set. Bounds memory so a
/// long-running bootstrap node cannot have the set grow without limit
/// from peer-id churn. Sized at 4x `MAX_LAST_COMMITMENT_BY_PEER` so
/// the set comfortably outlives normal LRU churn but still caps the
/// blast radius of identity-rotation attacks. Once full we refuse new
/// inserts (no eviction) — keeps the historic set stable; new v12
/// peers above the cap are treated as legacy on rejoin, which matches
/// the behaviour before this set existed, not a security regression.
const MAX_EVER_CAPABLE_PEERS: usize = 4 * MAX_LAST_COMMITMENT_BY_PEER;

// ---------------------------------------------------------------------------
// ReplicationEngine
// ---------------------------------------------------------------------------

/// The replication engine manages all replication background tasks and state.
pub struct ReplicationEngine {
    /// Replication configuration (shared across spawned tasks).
    config: Arc<ReplicationConfig>,
    /// P2P networking node.
    p2p_node: Arc<P2PNode>,
    /// Local chunk storage.
    storage: Arc<LmdbStorage>,
    /// Persistent paid-for-list.
    paid_list: Arc<PaidList>,
    /// Payment verifier for `PoP` validation.
    payment_verifier: Arc<PaymentVerifier>,
    /// Replication pipeline queues.
    queues: Arc<RwLock<ReplicationQueues>>,
    /// Neighbor sync cycle state.
    sync_state: Arc<RwLock<NeighborSyncState>>,
    /// Per-peer sync history (for `RepairOpportunity`).
    ///
    /// This map grows with peer churn and is intentionally unbounded: entries
    /// are lightweight (`PeerSyncRecord` is two fields) and peer IDs are
    /// naturally bounded by the routing table's k-bucket capacity.
    sync_history: Arc<RwLock<HashMap<PeerId, PeerSyncRecord>>>,
    /// Per-peer cooldown for gossip-triggered subtree audits (ADR-0002).
    ///
    /// Records when each peer was last audited so a burst of gossiped
    /// commitment changes cannot spawn back-to-back audits of the same peer.
    /// Bounded by routing-table membership and cleaned on `PeerRemoved`.
    audit_on_gossip_cooldown: Arc<RwLock<HashMap<PeerId, Instant>>>,
    /// Gossip-private lottery attempt window (one roll per peer per window,
    /// win or lose). Kept separate from `audit_on_gossip_cooldown` so a losing
    /// ticket never stamps the shared map and thus never defers a monetized
    /// first audit. Bounded like its sibling and cleaned on `PeerRemoved`.
    gossip_lottery_attempts: Arc<RwLock<HashMap<PeerId, Instant>>>,
    /// Completed local neighbor-sync cycle epoch for proof maturity.
    sync_cycle_epoch: Arc<RwLock<u64>>,
    /// Per-key repair proof tracking for audit eligibility.
    repair_proofs: Arc<RwLock<RepairProofs>>,
    /// Bootstrap state tracking.
    bootstrap_state: Arc<RwLock<BootstrapState>>,
    /// Whether this node is currently bootstrapping.
    is_bootstrapping: Arc<RwLock<bool>>,
    /// Trigger for early neighbor sync (signalled on topology changes).
    sync_trigger: Arc<Notify>,
    /// Notified when `is_bootstrapping` transitions from `true` to `false`.
    bootstrap_complete_notify: Arc<Notify>,
    /// Node identity (for signing storage commitments).
    ///
    /// Phase 3 of the v12 storage-bound audit design. The responder
    /// uses this to sign its periodically-built `StorageCommitment`.
    identity: Arc<NodeIdentity>,
    /// Responder-side commitment state (two-slot atomic rotation).
    ///
    /// Periodically rebuilt from the live LMDB key set; gossiped on
    /// outbound `NeighborSyncRequest`/`Response`; consulted by the
    /// commitment-bound audit handler.
    commitment_state: Arc<ResponderCommitmentState>,
    /// Path to the persisted responder retention snapshot
    /// (`{root_dir}/commitment_retention.bin`): reloaded on startup so an honest
    /// node's answerability survives restart (ADR-0004 A1), which is what makes
    /// removing audit grace safe (an unanswerable in-window pin is then provable
    /// misbehaviour, not an honest crash-restart).
    retention_path: PathBuf,
    /// Auditor-side per-peer commitment record (last known commitment +
    /// sticky `commitment_capable` flag).
    ///
    /// Populated whenever an inbound gossip carries a verified
    /// commitment from the sender. Used by `audit_tick` to snapshot
    /// `expected_commitment_hash` into outbound challenges, and by
    /// holder-eligibility (§6) to decide whether a peer's `recent_provers`
    /// proof should be honoured. The sticky `commitment_capable` flag
    /// flips true on first successful ingest and never reverts (§2
    /// step 5).
    last_commitment_by_peer: Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>>,
    /// Sticky set of peer IDs we have EVER seen carrying a v12
    /// commitment, independent of whether their commitment bytes are
    /// still in `last_commitment_by_peer`. The §6 holder-eligibility
    /// closure consults this set to keep treating churned-out
    /// previously-v12 peers as v12-capable (rather than degrading them
    /// to "legacy" credit-unconditionally) when they re-appear on the
    /// network before their next gossip arrives. Bounded growth: even
    /// at one million peers seen over the node's lifetime, the set is
    /// 32 MB.
    ever_capable_peers: Arc<RwLock<HashSet<PeerId>>>,
    /// Auditor-side holder-eligibility cache (v12 §6).
    ///
    /// Recorded on successful commitment-bound audit; read by future
    /// quorum / paid-list eligibility checks (phase-3 stretch).
    recent_provers: Arc<RwLock<RecentProvers>>,
    /// Per-peer last sig-verify attempt timestamp for the §2 step 3 /
    /// §11 `DoS` rate limit. Bumped on EVERY verify attempt (success or
    /// failure) so a peer we've never successfully verified can't burn
    /// CPU on a flood of structurally-plausible-but-invalid gossips.
    /// Lives separately from `last_commitment_by_peer` because that
    /// map's records only exist after a successful verify.
    sig_verify_attempts: Arc<RwLock<HashMap<PeerId, Instant>>>,
    /// Limits concurrent outbound replication sends to prevent bandwidth
    /// saturation on home broadband connections.
    send_semaphore: Arc<Semaphore>,
    /// Bounds concurrent IN-FLIGHT LIGHT audit-responder tasks (responsible-chunk
    /// audits + subtree slice round 2). The heavy subtree round 1 has its own
    /// tighter pool ([`SubtreeRound1Limiter`]). Those are spawned off the serial
    /// message loop so disk
    /// reads don't block replication; the semaphore restores a global
    /// backpressure ceiling so the node can't fan out unbounded `get_raw` reads
    /// / multi-MiB byte serves.
    audit_responder_semaphore: Arc<Semaphore>,
    /// Per-source in-flight audit-responder counts, capped at
    /// [`MAX_AUDIT_RESPONSES_PER_PEER`]. The GLOBAL semaphore alone is not
    /// flood-fair: one peer spamming challenges could occupy every slot and
    /// starve honest auditors, whose dropped challenges then convert to
    /// audit timeouts against HONEST peers (codex-r2 A). This
    /// per-peer cap guarantees no single source can hold more than its share,
    /// so a flood self-throttles without denying service to everyone else.
    audit_responder_inflight: Arc<RwLock<HashMap<PeerId, u32>>>,
    /// Resource controls for the HEAVY subtree-audit round 1: its own
    /// tight admission pool (so a burst of full-subtree hashing can't starve the
    /// light audits), a per-peer rate cooldown, and single-use round-1 → round-2
    /// sessions binding a slice challenge to a matching round 1.
    subtree_round1: SubtreeRound1Limiter,
    /// Receiver for fresh-write events from the chunk PUT handler.
    ///
    /// When present, `start()` spawns a drainer task that calls
    /// `replicate_fresh` for each event.
    fresh_write_rx: Option<mpsc::UnboundedReceiver<fresh::FreshWriteEvent>>,
    /// Sender for delayed possession-check events (ADR-0003). The fresh-write
    /// drainer pushes the responsible close-group peers here after each fresh
    /// replication; the possession-check scheduler drains the paired receiver.
    possession_check_tx: mpsc::UnboundedSender<possession::PossessionCheckEvent>,
    /// Receiver paired with `possession_check_tx`; taken by the scheduler task.
    possession_check_rx: Option<mpsc::UnboundedReceiver<possession::PossessionCheckEvent>>,
    /// ADR-0004: sender the payment verifier clones to surface monetized pins
    /// for a deterministic first audit. The matching receiver is drained by
    /// `start_first_audit_drainer`. BOUNDED (Amendment 2): the producer
    /// `try_send`s and drops on a full queue, so ingress memory is capped just
    /// like launches; a dropped nomination is penalty-free — the peer's
    /// gossiped commitments stay lottery-covered and its next settled payment
    /// re-nominates the paid pin.
    monetized_pin_tx: mpsc::Sender<MonetizedPinEvent>,
    /// ADR-0004: receiver half of the monetized-pin channel, taken by
    /// `start_first_audit_drainer`.
    monetized_pin_rx: Option<mpsc::Receiver<MonetizedPinEvent>>,
    /// Counters shared with the first-audit drainer task, so the scheduler's
    /// decisions (queued / launched / self-target skipped / outcome) stay
    /// observable from the engine after the drainer takes the receiver.
    first_audit_observability: Arc<FirstAuditObservability>,
    /// Shutdown token.
    shutdown: CancellationToken,
    /// Background task handles.
    task_handles: Vec<JoinHandle<()>>,
}

impl ReplicationEngine {
    /// Create a new replication engine.
    ///
    /// # Errors
    ///
    /// Returns an error if the `PaidList` LMDB environment cannot be opened
    /// or if the configuration fails validation.
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        config: ReplicationConfig,
        p2p_node: Arc<P2PNode>,
        storage: Arc<LmdbStorage>,
        payment_verifier: Arc<PaymentVerifier>,
        identity: Arc<NodeIdentity>,
        root_dir: &Path,
        fresh_write_rx: mpsc::UnboundedReceiver<fresh::FreshWriteEvent>,
        shutdown: CancellationToken,
    ) -> Result<Self> {
        config.validate().map_err(Error::Config)?;

        let paid_list = Arc::new(
            PaidList::new(root_dir)
                .await
                .map_err(|e| Error::Storage(format!("Failed to open PaidList: {e}")))?,
        );

        let initial_neighbors = NeighborSyncState::new_cycle(Vec::new());
        let config = Arc::new(config);
        let (possession_check_tx, possession_check_rx) = mpsc::unbounded_channel();

        // ADR-0004: monetized-pin channel (verifier -> first-audit drainer).
        // Bounded (Amendment 2): every stage of the first-audit pipeline is
        // now capacity-limited — ingress queue here, pending set (LRU), and
        // launch rate (token bucket).
        let (monetized_pin_tx, monetized_pin_rx) =
            mpsc::channel(config::FIRST_AUDIT_INGRESS_CAPACITY);

        let engine = Self {
            config: Arc::clone(&config),
            p2p_node,
            storage,
            paid_list,
            payment_verifier,
            queues: Arc::new(RwLock::new(ReplicationQueues::new())),
            sync_state: Arc::new(RwLock::new(initial_neighbors)),
            sync_history: Arc::new(RwLock::new(HashMap::new())),
            audit_on_gossip_cooldown: Arc::new(RwLock::new(HashMap::new())),
            gossip_lottery_attempts: Arc::new(RwLock::new(HashMap::new())),
            sync_cycle_epoch: Arc::new(RwLock::new(0)),
            repair_proofs: Arc::new(RwLock::new(RepairProofs::new())),
            bootstrap_state: Arc::new(RwLock::new(BootstrapState::new())),
            is_bootstrapping: Arc::new(RwLock::new(true)),
            sync_trigger: Arc::new(Notify::new()),
            bootstrap_complete_notify: Arc::new(Notify::new()),
            identity,
            commitment_state: Arc::new(ResponderCommitmentState::new()),
            retention_path: root_dir.join("commitment_retention.bin"),
            last_commitment_by_peer: Arc::new(RwLock::new(HashMap::new())),
            ever_capable_peers: Arc::new(RwLock::new(HashSet::new())),
            recent_provers: Arc::new(RwLock::new(RecentProvers::new())),
            sig_verify_attempts: Arc::new(RwLock::new(HashMap::new())),
            send_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_REPLICATION_SENDS)),
            audit_responder_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_AUDIT_RESPONSES)),
            audit_responder_inflight: Arc::new(RwLock::new(HashMap::new())),
            subtree_round1: SubtreeRound1Limiter::new(config.subtree_round1_responder_cooldown),
            fresh_write_rx: Some(fresh_write_rx),
            possession_check_tx,
            possession_check_rx: Some(possession_check_rx),
            monetized_pin_tx,
            monetized_pin_rx: Some(monetized_pin_rx),
            first_audit_observability: Arc::new(FirstAuditObservability::default()),
            shutdown,
            task_handles: Vec::new(),
        };
        // ADR-0004 A1: reload persisted responder retention BEFORE any task
        // spawns, so an honest restarted node is answerable for its pre-restart
        // pins from the first audit it serves, and the persist loop never races
        // an empty snapshot over the good on-disk file.
        load_commitment_retention(&engine.commitment_state, &engine.retention_path).await;
        Ok(engine)
    }

    /// ADR-0004: a sender the payment verifier uses to surface monetized pins
    /// (commitments that backed a payment) for a first audit. Cloneable; the
    /// engine drains the matching receiver. Bounded: senders must `try_send`
    /// and treat a full queue as a benign drop (Amendment 2 best-effort).
    #[must_use]
    pub fn monetized_pin_sender(&self) -> mpsc::Sender<MonetizedPinEvent> {
        self.monetized_pin_tx.clone()
    }

    /// Get a reference to the `PaidList`.
    #[must_use]
    pub fn paid_list(&self) -> &Arc<PaidList> {
        &self.paid_list
    }

    /// Get a reference to the responder's commitment state. Used by audit
    /// handlers to look up commitments by hash; used by the rotation tick
    /// to install fresh ones.
    #[must_use]
    pub fn commitment_state(&self) -> &Arc<ResponderCommitmentState> {
        &self.commitment_state
    }

    /// Get a reference to the auditor's last-commitment-by-peer table.
    #[must_use]
    pub fn last_commitment_by_peer(&self) -> &Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>> {
        &self.last_commitment_by_peer
    }

    /// Get a reference to the holder-eligibility cache. Phase-3 stretch:
    /// will be read by quorum / paid-list eligibility checks.
    #[must_use]
    pub fn recent_provers(&self) -> &Arc<RwLock<RecentProvers>> {
        &self.recent_provers
    }

    /// Test-only: rebuild + rotate this node's storage commitment now over its
    /// current key set (normally on a 1h timer). Lets a test commit to chunks it
    /// just stored without waiting for the rotation cadence.
    ///
    /// # Errors
    ///
    /// Propagates any error from reading the local key set or building/signing
    /// the commitment.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn rebuild_commitment_now(&self) -> Result<()> {
        rebuild_and_rotate_commitment(
            &self.storage,
            &self.identity,
            &self.commitment_state,
            &self.p2p_node,
            &self.config,
        )
        .await
    }

    /// Test-only: directly seed this node's cached commitment for `peer`,
    /// simulating "we received `peer`'s gossiped commitment" without depending
    /// on neighbor-sync propagation timing. Lets a two-node audit test pin the
    /// peer's commitment deterministically.
    #[cfg(any(feature = "test-utils", test))]
    pub async fn inject_peer_commitment_for_test(
        &self,
        peer: &PeerId,
        commitment: StorageCommitment,
    ) {
        let now = Instant::now();
        self.last_commitment_by_peer
            .write()
            .await
            .insert(*peer, PeerCommitmentRecord::from_verified(commitment, now));
        self.ever_capable_peers.write().await.insert(*peer);
    }

    /// Test-only: run ONE subtree audit against `peer` right now, pinned to the
    /// commitment this node has cached for it (from gossip), over the live wire.
    /// Returns the audit outcome so tests can assert honest-pass / adversary-fail
    /// in a real two-node setting without waiting for the gossip cadence.
    ///
    /// Returns `AuditTickResult::Idle` if we have no cached commitment for the
    /// peer yet (gossip hasn't reached us). Gated to test builds.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn audit_peer_now(&self, peer: &PeerId) -> audit::AuditTickResult {
        let target = {
            let map = self.last_commitment_by_peer.read().await;
            map.get(peer)
                .and_then(PeerCommitmentRecord::last_commitment)
                .and_then(|c| commitment_hash(c).map(|h| (h, c.key_count)))
        };
        let Some((pin, key_count)) = target else {
            return audit::AuditTickResult::Idle;
        };
        let credit = storage_commitment_audit::AuditCredit {
            recent_provers: &self.recent_provers,
        };
        storage_commitment_audit::run_subtree_audit(
            &self.p2p_node,
            &self.config,
            peer,
            pin,
            key_count,
            Some(&credit),
        )
        .await
    }

    /// Test-only: snapshot the first-audit scheduler's counters. Lets e2e
    /// tests assert what the live drainer decided for an injected
    /// [`MonetizedPinEvent`] (dropped as self-target vs queued and launched).
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn first_audit_stats(&self) -> FirstAuditStats {
        let o = &self.first_audit_observability;
        FirstAuditStats {
            received: o.received.load(Ordering::Relaxed),
            queued: o.queued.load(Ordering::Relaxed),
            self_target_skipped: o.self_target_skipped.load(Ordering::Relaxed),
            launched: o.launched.load(Ordering::Relaxed),
            passed: o.passed.load(Ordering::Relaxed),
            timed_out: o.timed_out.load(Ordering::Relaxed),
            failed: o.failed.load(Ordering::Relaxed),
        }
    }

    /// Test-only: run the possession check immediately for `key` against
    /// `peers`, bypassing the scheduler's randomised 5-15 minute settle delay.
    ///
    /// Penalises any peer that does not hold `key` at `AuditChallenge`
    /// severity (ADR-0003). Lets e2e tests assert the detection+penalty path
    /// deterministically without waiting for the scheduled check.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn run_possession_check_now(&self, key: XorName, peers: Vec<PeerId>) {
        possession::run_possession_check(
            key,
            peers,
            &self.p2p_node,
            &self.storage,
            &self.config,
            &self.sync_state,
            &self.shutdown,
        )
        .await;
    }

    /// Start all background tasks.
    ///
    /// `dht_events` must be subscribed **before** `P2PNode::start()` so that
    /// the `BootstrapComplete` event emitted during DHT bootstrap is not
    /// missed by the bootstrap-sync gate.
    pub fn start(&mut self, dht_events: tokio::sync::broadcast::Receiver<DhtNetworkEvent>) {
        if !self.task_handles.is_empty() {
            error!("ReplicationEngine::start() called while already running — ignoring");
            return;
        }
        info!("Starting replication engine");

        self.start_message_handler();
        self.start_neighbor_sync_loop();
        self.start_self_lookup_loop();
        // Audit #2 (responsible-chunk): periodic tick auditing peers for the
        // chunks they SHOULD store (responsibility + prior hint).
        self.start_audit_loop();
        // Audit #1 (storage-commitment) is gossip-triggered in the message
        // handler when a peer's commitment is ingested, not on a periodic tick.
        self.start_commitment_rotation_loop();
        self.start_retention_persist_loop();
        self.start_fetch_worker();
        self.start_verification_worker();
        self.start_bootstrap_sync(dht_events);
        self.start_fresh_write_drainer();
        self.start_possession_check_scheduler();
        // ADR-0004: deterministic first audit of commitments that backed a
        // payment (surfaced by the verifier cross-check).
        self.start_first_audit_drainer();
        // V2-623: periodic cumulative per-variant traffic accounting.
        self.start_traffic_summary_loop();

        info!(
            "Replication engine started with {} background tasks",
            self.task_handles.len()
        );
    }

    /// Returns `true` if the node is still in the replication bootstrap phase.
    ///
    /// During bootstrap, audit challenges return `Bootstrapping` instead of
    /// digests, and neighbor sync responses carry `bootstrapping: true`.
    pub async fn is_bootstrapping(&self) -> bool {
        *self.is_bootstrapping.read().await
    }

    /// Wait until the replication bootstrap phase completes.
    ///
    /// Returns immediately if bootstrap has already completed. Useful for
    /// readiness probes, health checks, and test harnesses that need the
    /// node to be fully operational before proceeding.
    ///
    /// Returns `true` if bootstrap completed within the timeout, `false`
    /// if the timeout elapsed first.
    pub async fn wait_for_bootstrap_complete(&self, timeout: Duration) -> bool {
        // Register the notification future *before* checking the flag so that
        // a transition between the read and the await is not missed.
        let notified = self.bootstrap_complete_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        if !*self.is_bootstrapping.read().await {
            return true;
        }

        tokio::time::timeout(timeout, notified).await.is_ok()
    }

    /// Cancel all background tasks and wait for them to terminate.
    ///
    /// This must be awaited before dropping the engine when the caller needs
    /// the `Arc<LmdbStorage>` references held by background tasks to be
    /// released (e.g. before reopening the same LMDB environment).
    pub async fn shutdown(&mut self) {
        self.shutdown.cancel();
        for (i, mut handle) in self.task_handles.drain(..).enumerate() {
            match tokio::time::timeout(std::time::Duration::from_secs(10), &mut handle).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) if e.is_cancelled() => {}
                Ok(Err(e)) => warn!("Replication task {i} panicked during shutdown: {e}"),
                Err(_) => {
                    warn!("Replication task {i} did not stop within 10s, aborting");
                    handle.abort();
                }
            }
        }
    }

    /// Trigger an early neighbor sync round.
    ///
    /// Useful after topology changes (new nodes joining, network heal after
    /// partition) when the caller wants replication to converge faster than
    /// the regular 10-20 minute cadence.
    pub fn trigger_neighbor_sync(&self) {
        self.sync_trigger.notify_one();
    }

    /// Execute fresh replication for a newly stored record, then schedule the
    /// delayed possession check for the responsible close-group peers
    /// (ADR-0003). The production PUT path schedules via the fresh-write
    /// drainer; this direct entry point schedules here so callers (and tests)
    /// that drive replication directly still get the possession check.
    pub async fn replicate_fresh(&self, key: &XorName, data: &[u8], proof_of_payment: &[u8]) {
        let peers = fresh::replicate_fresh(
            key,
            data,
            proof_of_payment,
            &self.p2p_node,
            &self.paid_list,
            &self.config,
            &self.send_semaphore,
        )
        .await;
        if !peers.is_empty() {
            let _ = self
                .possession_check_tx
                .send(possession::PossessionCheckEvent { key: *key, peers });
        }
    }

    // =======================================================================
    // Background task launchers
    // =======================================================================

    /// Spawn a task that drains the fresh-write channel and triggers
    /// replication for each newly-stored chunk.
    fn start_fresh_write_drainer(&mut self) {
        let Some(mut rx) = self.fresh_write_rx.take() else {
            return;
        };
        let p2p = Arc::clone(&self.p2p_node);
        let paid_list = Arc::clone(&self.paid_list);
        let config = Arc::clone(&self.config);
        let send_semaphore = Arc::clone(&self.send_semaphore);
        let possession_tx = self.possession_check_tx.clone();
        let shutdown = self.shutdown.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    event = rx.recv() => {
                        let Some(event) = event else { break };
                        let peers = fresh::replicate_fresh(
                            &event.key,
                            &event.data,
                            &event.payment_proof,
                            &p2p,
                            &paid_list,
                            &config,
                            &send_semaphore,
                        )
                        .await;
                        // Schedule the delayed possession check (ADR-0003) for
                        // the responsible close-group peers. A closed receiver
                        // (engine shutting down) is ignored.
                        if !peers.is_empty() {
                            let _ = possession_tx.send(possession::PossessionCheckEvent {
                                key: event.key,
                                peers,
                            });
                        }
                    }
                }
            }
            debug!("Fresh-write drainer shut down");
        });
        self.task_handles.push(handle);
    }

    /// Spawn the possession-check scheduler (ADR-0003).
    ///
    /// Drains scheduled possession-check events and, for each, waits a
    /// randomised 5-15 minute settle delay before probing every responsible
    /// peer for actual possession. A peer that cryptographically fails to prove
    /// possession is penalised at `AuditChallenge` severity. A peer that simply
    /// does not answer normally is too, but that is suspended for the
    /// possession-audit protocol rollout — see `GRACE_POSSESSION_AUDIT_TIMEOUTS`.
    fn start_possession_check_scheduler(&mut self) {
        let Some(mut rx) = self.possession_check_rx.take() else {
            return;
        };
        let p2p = Arc::clone(&self.p2p_node);
        let storage = Arc::clone(&self.storage);
        let config = Arc::clone(&self.config);
        let sync_state = Arc::clone(&self.sync_state);
        let shutdown = self.shutdown.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    event = rx.recv() => {
                        let Some(event) = event else { break };
                        // Spawn a per-chunk delayed check so the drain loop
                        // keeps pace with the write rate. Each check sleeps the
                        // randomised settle delay, then probes every peer.
                        let p2p = Arc::clone(&p2p);
                        let storage = Arc::clone(&storage);
                        let config = Arc::clone(&config);
                        let sync_state = Arc::clone(&sync_state);
                        let shutdown = shutdown.clone();
                        let delay_min = config.possession_check_delay_min;
                        let delay_max = config.possession_check_delay_max;
                        tokio::spawn(async move {
                            let delay = possession::random_delay(delay_min, delay_max);
                            tokio::select! {
                                () = shutdown.cancelled() => {}
                                () = tokio::time::sleep(delay) => {
                                    possession::run_possession_check(
                                        event.key,
                                        event.peers,
                                        &p2p,
                                        &storage,
                                        &config,
                                        &sync_state,
                                        &shutdown,
                                    )
                                    .await;
                                }
                            }
                        });
                    }
                }
            }
            debug!("Possession-check scheduler shut down");
        });
        self.task_handles.push(handle);
    }

    /// ADR-0004: drain monetized pins surfaced by the verifier cross-check and
    /// run a **deterministic first audit** of each — the same `run_subtree_audit`
    /// as the gossip path, under the same per-peer cooldown and concurrency
    /// caps, but with the probability lottery BYPASSED (the lottery governs
    /// re-audits only). Deduped by pin via a bounded set so a pin gets one
    /// deterministic first audit; a peer minting fresh pins faster than the
    /// cooldown forfeits the older ones' coverage, never the newest's (the
    /// channel surfaces newest pins as they are monetized).
    #[allow(clippy::too_many_lines)]
    fn start_first_audit_drainer(&mut self) {
        let Some(mut rx) = self.monetized_pin_rx.take() else {
            return;
        };
        let gossip_audit = GossipAuditTrigger {
            p2p_node: Arc::clone(&self.p2p_node),
            config: Arc::clone(&self.config),
            recent_provers: Arc::clone(&self.recent_provers),
            sync_state: Arc::clone(&self.sync_state),
            cooldown: Arc::clone(&self.audit_on_gossip_cooldown),
            lottery_attempts: Arc::clone(&self.gossip_lottery_attempts),
        };
        let shutdown = self.shutdown.clone();
        let observability = Arc::clone(&self.first_audit_observability);
        let self_peer = *self.p2p_node.peer_id();

        let handle = tokio::spawn(async move {
            // ADR-0004 Amendment 2 (E'): the drainer-owned first-audit
            // scheduler. Payments only NOMINATE pins; the token bucket launches
            // them at a fixed per-node rate, and durable suppression is stamped
            // only at PROMOTION (after an authoritative post-jitter answerability
            // + cooldown check), so a cancelled reservation leaves nothing behind.
            let mut scheduler = FirstAuditScheduler::new(Instant::now(), self_peer);
            // Periodic retry tick so budget/cooldown-deferred pins get retried
            // even when no new nomination arrives. `Skip` collapses a backlog.
            let mut tick = tokio::time::interval(config::FIRST_AUDIT_RETRY_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut last_summary = Instant::now();
            loop {
                // The reservation's jitter deadline is a wake source: if a
                // reservation is outstanding, sleep until it is due; otherwise
                // a far-future deadline effectively disables that arm and only
                // shutdown/rx/tick wake the loop. Recreated each iteration so a
                // newly reserved (earlier) deadline is honoured next turn.
                let promotion_due = scheduler
                    .reserved_ready_at()
                    .unwrap_or_else(first_audit_far_future);
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    event = rx.recv() => match event {
                        Some(e) => {
                            observability.received.fetch_add(1, Ordering::Relaxed);
                            // Pre-overflow reservation opportunity: before an
                            // arrival may displace a DIFFERENT peer, let the
                            // queue launch — a successful reservation frees the
                            // slot without eviction. One reservation can be
                            // outstanding at a time, so this consumes at most
                            // one slot per jitter window; arrivals beyond it
                            // fall through to random displacement (ADR-0004
                            // Amendment 4).
                            if scheduler.would_displace(&e) {
                                open_first_audit_reservation(
                                    &mut scheduler,
                                    &gossip_audit.cooldown,
                                    &observability,
                                )
                                .await;
                            }
                            scheduler.enqueue(e, &observability);
                            // Drain a bounded burst so a flood cannot starve the
                            // launch phase.
                            let mut drained = 1usize;
                            while drained < config::FIRST_AUDIT_DRAIN_BATCH {
                                match rx.try_recv() {
                                    Ok(e) => {
                                        observability.received.fetch_add(1, Ordering::Relaxed);
                                        if scheduler.would_displace(&e) {
                                            open_first_audit_reservation(
                                                &mut scheduler,
                                                &gossip_audit.cooldown,
                                                &observability,
                                            )
                                            .await;
                                        }
                                        scheduler.enqueue(e, &observability);
                                        drained += 1;
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                        None => break,
                    },
                    _ = tick.tick() => {}
                    () = tokio::time::sleep_until(promotion_due.into()) => {}
                }

                // 1) Promote a due reservation. Resolved after EVERY wake (not
                //    only when the timer arm wins) so a continuously-ready `rx`
                //    cannot indefinitely delay a due promotion. The authoritative
                //    answerability + cooldown check-and-stamp happens here under
                //    the shared cooldown write lock, immediately before the send.
                if let Some(reservation) = scheduler.take_due_reservation(Instant::now()) {
                    let promoted = {
                        let mut cooldown = gossip_audit.cooldown.write().await;
                        scheduler.resolve(
                            reservation,
                            SystemTime::now(),
                            Instant::now(),
                            &mut cooldown,
                            &observability,
                        )
                    };
                    if let Some((event, inflight_slot)) = promoted {
                        debug!(
                            "First-audit scheduler: audit_trigger=first_monetized outcome=launched peer={} pin={} key_count={} inflight={}",
                            event.peer, hex::encode(event.pin), event.key_count,
                            observability.inflight.load(Ordering::Relaxed)
                        );
                        let trigger = gossip_audit.clone();
                        let audit_observability = Arc::clone(&observability);
                        tokio::spawn(async move {
                            // The jitter already elapsed as the reservation's
                            // timer; the slot is held for the audit's duration
                            // and released on drop (panic-safe).
                            let inflight_slot = inflight_slot;
                            let started = Instant::now();
                            let credit = storage_commitment_audit::AuditCredit {
                                recent_provers: &trigger.recent_provers,
                            };
                            let result = storage_commitment_audit::run_subtree_audit(
                                &trigger.p2p_node,
                                &trigger.config,
                                &event.peer,
                                event.pin,
                                event.key_count,
                                Some(&credit),
                            )
                            .await;
                            let outcome = first_audit_terminal_outcome(&result);
                            match outcome {
                                FirstAuditTerminalOutcome::Passed => {
                                    audit_observability.passed.fetch_add(1, Ordering::Relaxed);
                                }
                                FirstAuditTerminalOutcome::Timeout => {
                                    audit_observability
                                        .timed_out
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                                FirstAuditTerminalOutcome::Failed => {
                                    audit_observability.failed.fetch_add(1, Ordering::Relaxed);
                                }
                                FirstAuditTerminalOutcome::BootstrapClaim => {
                                    audit_observability
                                        .bootstrap_claims
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                                FirstAuditTerminalOutcome::Idle => {
                                    audit_observability.idle.fetch_add(1, Ordering::Relaxed);
                                }
                                FirstAuditTerminalOutcome::InsufficientKeys => {
                                    audit_observability
                                        .insufficient_keys
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            drop(inflight_slot);
                            debug!(
                                "First-audit scheduler: audit_trigger=first_monetized outcome={} peer={} pin={} key_count={} elapsed_ms={} inflight={}",
                                outcome.as_str(),
                                event.peer, hex::encode(event.pin), event.key_count,
                                started.elapsed().as_millis(),
                                audit_observability.inflight.load(Ordering::Relaxed)
                            );
                            handle_subtree_audit_result(
                                &result,
                                &trigger.p2p_node,
                                &trigger.sync_state,
                                &trigger.recent_provers,
                                &trigger.config,
                            )
                            .await;
                        });
                    }
                }

                // 2) Open the single reservation from the pending queue if none
                //    is outstanding (read-only cooldown snapshot; the
                //    authoritative stamp is at promotion). Serializing
                //    reservations preserves per-launch lane alternation and keeps
                //    at most one jitter timer live.
                open_first_audit_reservation(
                    &mut scheduler,
                    &gossip_audit.cooldown,
                    &observability,
                )
                .await;

                if last_summary.elapsed() >= config::FIRST_AUDIT_SUMMARY_INTERVAL {
                    // Token-independent hygiene: collect entries that aged past
                    // the answerability horizon while the budget gate kept the
                    // reserve scan from running, so the summary below reports
                    // only live work.
                    let swept = scheduler.sweep_expired(SystemTime::now(), &observability);
                    if swept > 0 {
                        debug!(
                            "First-audit scheduler: audit_trigger=first_monetized outcome=expired_swept count={swept} pending={}",
                            scheduler.pending_len()
                        );
                    }
                    info!(
                        "First-audit scheduler summary: audit_trigger=first_monetized ingress_dropped={} received={} queued={} coalesced={} suppressed_lower={} duplicates={} capacity_evicted={} self_target_skipped={} cooldown_deferred_attempts={} rate_deferred_attempts={} window_deduped={} launched={} passed={} timeout={} failed={} bootstrap_claims={} idle={} insufficient_keys={} outside_answerability_window={} pending={} pending_cap={} reserved={} oldest_pending_quote_age_ms={} inflight={} tokens={}",
                        FIRST_AUDIT_INGRESS_DROPPED.load(Ordering::Relaxed),
                        observability.received.load(Ordering::Relaxed),
                        observability.queued.load(Ordering::Relaxed),
                        observability.coalesced.load(Ordering::Relaxed),
                        observability.suppressed_lower.load(Ordering::Relaxed),
                        observability.duplicates.load(Ordering::Relaxed),
                        observability.capacity_evicted.load(Ordering::Relaxed),
                        observability.self_target_skipped.load(Ordering::Relaxed),
                        observability.cooldown_deferred_attempts.load(Ordering::Relaxed),
                        observability.rate_deferred_attempts.load(Ordering::Relaxed),
                        observability.window_deduped.load(Ordering::Relaxed),
                        observability.launched.load(Ordering::Relaxed),
                        observability.passed.load(Ordering::Relaxed),
                        observability.timed_out.load(Ordering::Relaxed),
                        observability.failed.load(Ordering::Relaxed),
                        observability.bootstrap_claims.load(Ordering::Relaxed),
                        observability.idle.load(Ordering::Relaxed),
                        observability.insufficient_keys.load(Ordering::Relaxed),
                        observability.outside_answerability_window.load(Ordering::Relaxed),
                        scheduler.pending_len(),
                        FIRST_AUDIT_PENDING_CAP,
                        u8::from(scheduler.has_reservation()),
                        scheduler.oldest_pending_quote_age_ms(SystemTime::now()),
                        observability.inflight.load(Ordering::Relaxed),
                        scheduler.tokens(),
                    );
                    last_summary = Instant::now();
                }
            }
            debug!("First-audit drainer shut down");
        });
        self.task_handles.push(handle);
    }

    #[allow(clippy::too_many_lines)]
    fn start_message_handler(&mut self) {
        let mut p2p_events = self.p2p_node.subscribe_events();
        let mut dht_events = self.p2p_node.dht_manager().subscribe_events();
        let p2p = Arc::clone(&self.p2p_node);
        let storage = Arc::clone(&self.storage);
        let paid_list = Arc::clone(&self.paid_list);
        let payment_verifier = Arc::clone(&self.payment_verifier);
        let queues = Arc::clone(&self.queues);
        let config = Arc::clone(&self.config);
        let shutdown = self.shutdown.clone();
        let is_bootstrapping = Arc::clone(&self.is_bootstrapping);
        let bootstrap_state = Arc::clone(&self.bootstrap_state);
        let sync_history = Arc::clone(&self.sync_history);
        let sync_cycle_epoch = Arc::clone(&self.sync_cycle_epoch);
        let repair_proofs = Arc::clone(&self.repair_proofs);
        let sync_trigger = Arc::clone(&self.sync_trigger);
        let my_commitment_state = Arc::clone(&self.commitment_state);
        let last_commitment_by_peer = Arc::clone(&self.last_commitment_by_peer);
        let ever_capable_peers = Arc::clone(&self.ever_capable_peers);
        let recent_provers = Arc::clone(&self.recent_provers);
        let sig_verify_attempts = Arc::clone(&self.sig_verify_attempts);
        let audit_on_gossip_cooldown = Arc::clone(&self.audit_on_gossip_cooldown);
        let gossip_lottery_attempts = Arc::clone(&self.gossip_lottery_attempts);
        let sync_state = Arc::clone(&self.sync_state);
        let audit_responder_semaphore = Arc::clone(&self.audit_responder_semaphore);
        let audit_responder_inflight = Arc::clone(&self.audit_responder_inflight);
        let subtree_round1 = self.subtree_round1.clone();

        // ADR-0002 gossip-audit trigger: bundled state so an ingested *changed*
        // commitment can spawn a probabilistic, cooldown-gated subtree audit.
        let gossip_audit = GossipAuditTrigger {
            p2p_node: Arc::clone(&p2p),
            config: Arc::clone(&config),
            recent_provers: Arc::clone(&recent_provers),
            sync_state: Arc::clone(&sync_state),
            cooldown: Arc::clone(&audit_on_gossip_cooldown),
            lottery_attempts: Arc::clone(&gossip_lottery_attempts),
        };

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    event = p2p_events.recv() => {
                        let Ok(event) = event else { continue };
                        if let P2PEvent::Message {
                            topic,
                            source: Some(source),
                            data,
                            ..
                        } = event {
                            // Determine which replication protocol this message
                            // rode (core or subtree-audit) and whether it arrived
                            // via the /rr/ request-response path (which wraps
                            // payloads in a RequestResponseEnvelope).
                            let rr_info = match_replication_protocol(&topic).and_then(
                                |(matched_id, is_rr)| {
                                    if is_rr {
                                        P2PNode::parse_request_envelope(&data)
                                            .filter(|(_, is_resp, _)| !is_resp)
                                            .map(|(msg_id, _, payload)| {
                                                (matched_id, payload, Some(msg_id))
                                            })
                                    } else {
                                        Some((matched_id, data.clone(), None))
                                    }
                                },
                            );
                            if let Some((matched_id, payload, rr_message_id)) = rr_info {
                                match handle_replication_message(
                                    &source,
                                    &payload,
                                    matched_id,
                                    &p2p,
                                    &storage,
                                    &paid_list,
                                    &payment_verifier,
                                    &queues,
                                    &config,
                                    &is_bootstrapping,
                                    &bootstrap_state,
                                    &sync_history,
                                    &sync_cycle_epoch,
                                    &repair_proofs,
                                    &last_commitment_by_peer,
                                    &ever_capable_peers,
                                    &sig_verify_attempts,
                                    &my_commitment_state,
                                    &gossip_audit,
                                    &audit_responder_semaphore,
                                    &audit_responder_inflight,
                                    &subtree_round1,
                                    rr_message_id.as_deref(),
                                ).await {
                                    Ok(()) => {}
                                    Err(e) => {
                                        debug!(
                                            "Replication message from {source} error: {e}"
                                        );
                                    }
                                }
                            }
                        }
                    }
                    // Gap 4: Topology churn handling (Section 13).
                    //
                    // The DHT routing table emits KClosestPeersChanged when the
                    // K-closest peer set actually changes, which is the precise
                    // signal for triggering neighbor sync. This replaces the
                    // previous approach of checking every PeerConnected /
                    // PeerDisconnected event against the close group.
                    dht_event = dht_events.recv() => {
                        let Ok(dht_event) = dht_event else { continue };
                        match dht_event {
                            DhtNetworkEvent::KClosestPeersChanged { old, new } => {
                                let old_peers = old
                                    .iter()
                                    .take(config.neighbor_sync_scope)
                                    .copied()
                                    .collect::<HashSet<_>>();
                                let new_scoped = new
                                    .iter()
                                    .take(config.neighbor_sync_scope)
                                    .copied()
                                    .collect::<Vec<_>>();
                                let new_peers =
                                    new_scoped.iter().copied().collect::<HashSet<_>>();
                                let entrants = new_scoped
                                    .iter()
                                    .copied()
                                    .filter(|peer| !old_peers.contains(peer))
                                    .collect::<Vec<_>>();
                                let entrant_count = entrants.len();
                                let (priority_insertions, sync_removals) = {
                                    let mut state = sync_state.write().await;
                                    let sync_removals = state.retain_sync_peers(&new_peers);
                                    let priority_insertions = state.queue_priority_peers(entrants);
                                    (priority_insertions, sync_removals)
                                };
                                if priority_insertions > 0 {
                                    debug!(
                                        "K-closest peers changed, queued {priority_insertions}/{entrant_count} new close peers for priority neighbor sync and pruned {sync_removals} departed pending sync entries"
                                    );
                                } else {
                                    debug!(
                                        "K-closest peers changed, no additional close peers queued, pruned {sync_removals} departed pending sync entries, triggering early neighbor sync"
                                    );
                                }
                                sync_trigger.notify_one();
                            }
                            DhtNetworkEvent::PeerRemoved { peer_id } => {
                                sync_state.write().await.remove_peer(&peer_id);
                                repair_proofs.write().await.remove_peer(&peer_id);
                                // v12: drop the commitment bytes and the
                                // recent-prover credit so a churn / sybil
                                // attacker cannot leave behind one
                                // StorageCommitment per identity in
                                // `last_commitment_by_peer`. Also drop the
                                // sig-verify rate-limit timestamp.
                                last_commitment_by_peer.write().await.remove(&peer_id);
                                recent_provers.write().await.forget_peer(&peer_id);
                                sig_verify_attempts.write().await.remove(&peer_id);
                                // Same for the gossip-audit cooldown (ADR-0002)
                                // and the lottery-attempt window.
                                audit_on_gossip_cooldown.write().await.remove(&peer_id);
                                gossip_lottery_attempts.write().await.remove(&peer_id);
                                // The sticky `commitment_capable` flag is
                                // preserved orthogonally via
                                // `ever_capable_peers` — even after this
                                // removal, a re-joining peer continues to
                                // be treated as v12-capable rather than
                                // legacy (§3 shield).
                            }
                            _ => {}
                        }
                    }
                }
            }
            debug!("Replication message handler shut down");
        });
        self.task_handles.push(handle);
    }

    fn start_neighbor_sync_loop(&mut self) {
        let p2p = Arc::clone(&self.p2p_node);
        let storage = Arc::clone(&self.storage);
        let paid_list = Arc::clone(&self.paid_list);
        let queues = Arc::clone(&self.queues);
        let config = Arc::clone(&self.config);
        let shutdown = self.shutdown.clone();
        let sync_state = Arc::clone(&self.sync_state);
        let sync_history = Arc::clone(&self.sync_history);
        let sync_cycle_epoch = Arc::clone(&self.sync_cycle_epoch);
        let repair_proofs = Arc::clone(&self.repair_proofs);
        let is_bootstrapping = Arc::clone(&self.is_bootstrapping);
        let bootstrap_state = Arc::clone(&self.bootstrap_state);
        let sync_trigger = Arc::clone(&self.sync_trigger);
        let commitment_state = Arc::clone(&self.commitment_state);
        let last_commitment_by_peer = Arc::clone(&self.last_commitment_by_peer);
        let ever_capable_peers = Arc::clone(&self.ever_capable_peers);
        let sig_verify_attempts = Arc::clone(&self.sig_verify_attempts);
        // ADR-0002: a peer's commitment also arrives on the sync RESPONSE path
        // (we initiated, they piggybacked theirs). Carry a gossip-audit trigger
        // here too so a peer that only ever answers — never initiates sync —
        // is still audited; otherwise it could fully evade auditing.
        let gossip_audit = GossipAuditTrigger {
            p2p_node: Arc::clone(&p2p),
            config: Arc::clone(&config),
            recent_provers: Arc::clone(&self.recent_provers),
            sync_state: Arc::clone(&sync_state),
            cooldown: Arc::clone(&self.audit_on_gossip_cooldown),
            lottery_attempts: Arc::clone(&self.gossip_lottery_attempts),
        };

        let handle = tokio::spawn(async move {
            loop {
                let interval = config.random_neighbor_sync_interval();
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(interval) => {}
                    () = sync_trigger.notified() => {
                        debug!("Neighbor sync triggered by topology change");
                    }
                }
                // Wrap the sync round in a select so shutdown cancels
                // in-progress network operations rather than waiting for
                // the full round to complete.
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = run_neighbor_sync_round(
                        &p2p,
                        &storage,
                        &paid_list,
                        &queues,
                        &config,
                        &sync_state,
                        &sync_history,
                        &sync_cycle_epoch,
                        &repair_proofs,
                        &is_bootstrapping,
                        &bootstrap_state,
                        &commitment_state,
                        &last_commitment_by_peer,
                        &ever_capable_peers,
                        &sig_verify_attempts,
                        &gossip_audit,
                    ) => {}
                }
            }
            debug!("Neighbor sync loop shut down");
        });
        self.task_handles.push(handle);
    }

    fn start_self_lookup_loop(&mut self) {
        let p2p = Arc::clone(&self.p2p_node);
        let config = Arc::clone(&self.config);
        let shutdown = self.shutdown.clone();

        let handle = tokio::spawn(async move {
            loop {
                let interval = config.random_self_lookup_interval();
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(interval) => {
                        if let Err(e) = p2p.dht_manager().trigger_self_lookup().await {
                            debug!("Self-lookup failed: {e}");
                        }
                    }
                }
            }
            debug!("Self-lookup loop shut down");
        });
        self.task_handles.push(handle);
    }

    /// Periodic responsible-chunk audit loop (audit #2): every
    /// [`ReplicationConfig::random_audit_tick_interval`] (~10-20 min), audit one
    /// eligible close peer for the chunks it *should* be storing (by
    /// responsibility and prior repair hint), independent of the gossip-triggered
    /// storage-commitment audit. Waits for bootstrap to drain, then runs one tick
    /// immediately and periodically thereafter.
    fn start_audit_loop(&mut self) {
        let p2p = Arc::clone(&self.p2p_node);
        let storage = Arc::clone(&self.storage);
        let config = Arc::clone(&self.config);
        let shutdown = self.shutdown.clone();
        let sync_history = Arc::clone(&self.sync_history);
        let sync_cycle_epoch = Arc::clone(&self.sync_cycle_epoch);
        let repair_proofs = Arc::clone(&self.repair_proofs);
        let bootstrap_state = Arc::clone(&self.bootstrap_state);
        let is_bootstrapping = Arc::clone(&self.is_bootstrapping);
        let sync_state = Arc::clone(&self.sync_state);

        let handle = tokio::spawn(async move {
            // Invariant 19: wait for bootstrap to drain before starting audits.
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => return,
                    () = tokio::time::sleep(
                        std::time::Duration::from_secs(BOOTSTRAP_DRAIN_CHECK_SECS)
                    ) => {
                        if bootstrap_state.read().await.is_drained() {
                            break;
                        }
                    }
                }
            }

            // Run one audit tick immediately after bootstrap drain.
            {
                let bootstrapping = *is_bootstrapping.read().await;
                let result = {
                    let history = sync_history.read().await;
                    let current_sync_epoch = *sync_cycle_epoch.read().await;
                    audit::audit_tick_with_repair_proofs(
                        &p2p,
                        &storage,
                        &config,
                        &history,
                        &repair_proofs,
                        current_sync_epoch,
                        bootstrapping,
                    )
                    .await
                };
                handle_audit_result(&result, &p2p, &sync_state, &config).await;
            }

            // Then run periodically.
            loop {
                let interval = config.random_audit_tick_interval();
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(interval) => {
                        let bootstrapping = *is_bootstrapping.read().await;
                        let result = {
                            let history = sync_history.read().await;
                            let current_sync_epoch = *sync_cycle_epoch.read().await;
                            audit::audit_tick_with_repair_proofs(
                                &p2p,
                                &storage,
                                &config,
                                &history,
                                &repair_proofs,
                                current_sync_epoch,
                                bootstrapping,
                            )
                            .await
                        };
                        handle_audit_result(&result, &p2p, &sync_state, &config).await;
                    }
                }
            }
            debug!("Audit loop shut down");
        });
        self.task_handles.push(handle);
    }

    /// Periodically rebuild + sign + rotate the responder's storage
    /// commitment.
    ///
    /// Phase 3 of the v12 storage-bound audit. Once per
    /// [`COMMITMENT_ROTATION_INTERVAL_SECS`], the responder reads the
    /// current LMDB key set, builds a Merkle tree (for content-addressed
    /// chunks `bytes_hash == key`, so no chunk re-read is needed), signs
    /// the root with the node's `MlDsaSecretKey`, and rotates the result
    /// into `commitment_state`. Old `previous` slot is dropped by the
    /// rotate (per `ResponderCommitmentState::rotate`).
    ///
    /// Skips if the key set is empty (no commitment to make) — the
    /// auditor side falls back to the legacy plain-digest path for
    /// peers that have never gossiped a commitment.
    fn start_commitment_rotation_loop(&mut self) {
        let storage = Arc::clone(&self.storage);
        let identity = Arc::clone(&self.identity);
        let commitment_state = Arc::clone(&self.commitment_state);
        let shutdown = self.shutdown.clone();
        let p2p = Arc::clone(&self.p2p_node);
        let config = Arc::clone(&self.config);
        let sync_trigger = Arc::clone(&self.sync_trigger);
        let recent_provers = Arc::clone(&self.recent_provers);

        let handle = tokio::spawn(async move {
            // Build the first commitment immediately on startup so a
            // restarted node can answer commitment-bound audits right
            // away — otherwise current() stays None for a full rotation
            // interval and audits silently fall back to legacy.
            //
            // After the first build, trigger an immediate neighbor-sync
            // round so the new commitment gossips out within seconds.
            // Without this, after a restart remote auditors keep pinning
            // the pre-restart (rotated-away) hash until their normal
            // sync cadence elapses — up to 1 h in the worst case,
            // during which time commitment-bound audits hit "unknown
            // commitment hash" -> Idle no-ops.
            // ML-DSA signatures are randomized so we cannot reproduce
            // the pre-restart hash; the only honest path to recovery
            // is fast re-gossip.
            // ADR-0004 A1: retention was reloaded in `new()` (before any task
            // spawned), so this initial rebuild no-ops when the key set is
            // unchanged — preserving the reloaded current pin; otherwise the
            // reloaded roots stay answerable as retained slots until their gossip
            // TTL lapses. Persistence is handled by the retention-persist loop.
            if let Err(e) =
                rebuild_and_rotate_commitment(&storage, &identity, &commitment_state, &p2p, &config)
                    .await
            {
                warn!("Initial commitment build failed: {e}");
            } else {
                sync_trigger.notify_one();
            }
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(
                        std::time::Duration::from_secs(COMMITMENT_ROTATION_INTERVAL_SECS)
                    ) => {
                        if let Err(e) = rebuild_and_rotate_commitment(
                            &storage,
                            &identity,
                            &commitment_state,
                            &p2p,
                            &config,
                        ).await {
                            warn!("Commitment rotation failed: {e}");
                        }
                        // Piggyback a sweep of expired recent_provers
                        // entries on the rotation tick (same cadence,
                        // 1 h). is_credited_holder already honours the
                        // TTL on read, but the sweep reclaims memory
                        // for entries we'll never re-read.
                        let dropped = recent_provers.write().await.sweep_expired(
                            std::time::Instant::now()
                        );
                        if dropped > 0 {
                            debug!("recent_provers: swept {dropped} expired entries");
                        }
                    }
                }
            }
            debug!("Commitment rotation loop shut down");
        });
        self.task_handles.push(handle);
    }

    /// ADR-0004 A1: periodically flush the responder retention snapshot to disk
    /// (write-on-change) so answerability — including gossip-stamp refreshes and
    /// rotations — survives a restart. Flushes once immediately, then every
    /// `RETENTION_PERSIST_INTERVAL_SECS`, and once more on shutdown.
    fn start_retention_persist_loop(&mut self) {
        let commitment_state = Arc::clone(&self.commitment_state);
        let retention_path = self.retention_path.clone();
        let shutdown = self.shutdown.clone();
        let handle = tokio::spawn(async move {
            let mut last: Option<Vec<u8>> = None;
            persist_retention_if_changed(&commitment_state, &retention_path, &mut last).await;
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => {
                        persist_retention_if_changed(&commitment_state, &retention_path, &mut last)
                            .await;
                        break;
                    }
                    () = tokio::time::sleep(std::time::Duration::from_secs(
                        RETENTION_PERSIST_INTERVAL_SECS,
                    )) => {
                        persist_retention_if_changed(&commitment_state, &retention_path, &mut last)
                            .await;
                    }
                }
            }
            debug!("Commitment retention persist loop shut down");
        });
        self.task_handles.push(handle);
    }

    /// Periodically emit the cumulative replication traffic summaries: the
    /// per-variant line (V2-623) and the per-peer top-10 served-bytes line
    /// (V2-684). Both read process-global counter tables maintained by the
    /// encode/decode and serve choke points in [`protocol`]; needs no engine
    /// state.
    fn start_traffic_summary_loop(&mut self) {
        let shutdown = self.shutdown.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(std::time::Duration::from_secs(
                        TRAFFIC_SUMMARY_INTERVAL_SECS,
                    )) => {
                        protocol::log_traffic_summary();
                        protocol::log_served_peers_summary();
                        protocol::log_audit_outcome_summary();
                    }
                }
            }
            debug!("Replication traffic summary loop shut down");
        });
        self.task_handles.push(handle);
    }

    #[allow(clippy::too_many_lines, clippy::option_if_let_else)]
    fn start_fetch_worker(&mut self) {
        let p2p = Arc::clone(&self.p2p_node);
        let storage = Arc::clone(&self.storage);
        let queues = Arc::clone(&self.queues);
        let config = Arc::clone(&self.config);
        let shutdown = self.shutdown.clone();
        let bootstrap_state = Arc::clone(&self.bootstrap_state);
        let is_bootstrapping = Arc::clone(&self.is_bootstrapping);
        let bootstrap_complete_notify = Arc::clone(&self.bootstrap_complete_notify);
        let concurrency = max_parallel_fetch();

        info!("Fetch worker concurrency set to {concurrency} (hardware threads)");

        let handle = tokio::spawn(async move {
            // Each in-flight future yields (key, Option<FetchOutcome>) so we
            // always recover the key — even if the inner task panics.
            let mut in_flight = FuturesUnordered::<FetchFuture>::new();

            loop {
                // Fill up to `concurrency` slots from the queue.
                {
                    let mut q = queues.write().await;
                    while in_flight.len() < concurrency {
                        let Some(candidate) = q.dequeue_fetch() else {
                            break;
                        };
                        let Some(&source) = candidate.sources.first() else {
                            warn!(
                                "Fetch candidate {} has no sources — dropping",
                                hex::encode(candidate.key)
                            );
                            continue;
                        };
                        q.start_fetch(candidate.key, source, candidate.sources.clone());

                        let p2p = Arc::clone(&p2p);
                        let storage = Arc::clone(&storage);
                        let config = Arc::clone(&config);
                        let token = shutdown.clone();
                        let fetch_key = candidate.key;
                        in_flight.push(Box::pin(async move {
                            let handle = tokio::spawn(async move {
                                // Cancel-aware: abort when the engine shuts down.
                                tokio::select! {
                                    () = token.cancelled() => FetchOutcome {
                                        key: fetch_key,
                                        result: FetchResult::SourceFailed,
                                    },
                                    outcome = execute_single_fetch(
                                        p2p, storage, config, fetch_key, source,
                                    ) => outcome,
                                }
                            });
                            match handle.await {
                                Ok(outcome) => (outcome.key, Some(outcome)),
                                Err(e) => {
                                    error!(
                                        "Fetch task for {} panicked: {e}",
                                        hex::encode(fetch_key)
                                    );
                                    (fetch_key, None)
                                }
                            }
                        }));
                    }
                } // release queues write lock

                if in_flight.is_empty() {
                    // No work — wait for new items or shutdown.
                    tokio::select! {
                        () = shutdown.cancelled() => break,
                        () = tokio::time::sleep(
                            std::time::Duration::from_millis(FETCH_WORKER_POLL_MS)
                        ) => continue,
                    }
                }

                // Wait for the next fetch to complete and process the result.
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    Some((key, maybe_outcome)) = in_flight.next() => {
                        let mut q = queues.write().await;
                        let terminal = if let Some(outcome) = maybe_outcome {
                            match outcome.result {
                                FetchResult::Stored => {
                                    q.complete_fetch(&key);
                                    true
                                }
                                FetchResult::IntegrityFailed | FetchResult::SourceFailed => {
                                    if let Some(next_peer) = q.retry_fetch(&key) {
                                        // Spawn a new fetch task for the next source.
                                        let p2p = Arc::clone(&p2p);
                                        let storage = Arc::clone(&storage);
                                        let config = Arc::clone(&config);
                                        let token = shutdown.clone();
                                        let fetch_key = key;
                                        in_flight.push(Box::pin(async move {
                                            let handle = tokio::spawn(async move {
                                                tokio::select! {
                                                    () = token.cancelled() => FetchOutcome {
                                                        key: fetch_key,
                                                        result: FetchResult::SourceFailed,
                                                    },
                                                    outcome = execute_single_fetch(
                                                        p2p, storage, config, fetch_key, next_peer,
                                                    ) => outcome,
                                                }
                                            });
                                            match handle.await {
                                                Ok(outcome) => (outcome.key, Some(outcome)),
                                                Err(e) => {
                                                    error!(
                                                        "Fetch task for {} panicked: {e}",
                                                        hex::encode(fetch_key)
                                                    );
                                                    (fetch_key, None)
                                                }
                                            }
                                        }));
                                        false
                                    } else {
                                        q.complete_fetch(&key);
                                        true
                                    }
                                }
                            }
                        } else {
                            // Task panicked — reclaim the in-flight slot.
                            q.complete_fetch(&key);
                            true
                        };

                        // Shrink bootstrap pending set on terminal exit.
                        if terminal {
                            drop(q); // release queues lock before acquiring bootstrap_state
                            if !bootstrap_state.read().await.is_drained() {
                                bootstrap_state.write().await.remove_key(&key);
                                let q = queues.read().await;
                                if bootstrap::check_bootstrap_drained(
                                    &bootstrap_state,
                                    &q,
                                )
                                .await
                                {
                                    complete_bootstrap(
                                        &is_bootstrapping,
                                        &bootstrap_complete_notify,
                                    ).await;
                                }
                            }
                        }
                    }
                }
            }

            // Cancel and drain remaining in-flight fetches on shutdown.
            // The CancellationToken is already cancelled by this point, so
            // spawned tasks will see cancellation via their select! branches.
            while in_flight.next().await.is_some() {}
            debug!("Fetch worker shut down");
        });
        self.task_handles.push(handle);
    }

    fn start_verification_worker(&mut self) {
        let p2p = Arc::clone(&self.p2p_node);
        let storage = Arc::clone(&self.storage);
        let queues = Arc::clone(&self.queues);
        let paid_list = Arc::clone(&self.paid_list);
        let config = Arc::clone(&self.config);
        let shutdown = self.shutdown.clone();
        let bootstrap_state = Arc::clone(&self.bootstrap_state);
        let is_bootstrapping = Arc::clone(&self.is_bootstrapping);
        let bootstrap_complete_notify = Arc::clone(&self.bootstrap_complete_notify);
        let last_commitment_by_peer = Arc::clone(&self.last_commitment_by_peer);
        let ever_capable_peers = Arc::clone(&self.ever_capable_peers);
        let recent_provers = Arc::clone(&self.recent_provers);

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(
                        std::time::Duration::from_millis(VERIFICATION_WORKER_POLL_MS)
                    ) => {
                        let ctx = VerificationCycleContext {
                            p2p_node: &p2p,
                            paid_list: &paid_list,
                            storage: &storage,
                            queues: &queues,
                            config: &config,
                            bootstrap_state: &bootstrap_state,
                            is_bootstrapping: &is_bootstrapping,
                            bootstrap_complete_notify: &bootstrap_complete_notify,
                            last_commitment_by_peer: &last_commitment_by_peer,
                            ever_capable_peers: &ever_capable_peers,
                            recent_provers: &recent_provers,
                        };
                        run_verification_cycle(ctx).await;
                    }
                }
            }
            debug!("Verification worker shut down");
        });
        self.task_handles.push(handle);
    }

    /// Gap 3: Run a one-shot bootstrap sync on startup.
    ///
    /// Waits for saorsa-core to emit `DhtNetworkEvent::BootstrapComplete`
    /// (indicating the routing table is populated) before snapshotting
    /// close neighbors. Falls back after a timeout so bootstrap nodes
    /// (which have no peers and therefore never receive the event) still
    /// proceed.
    ///
    /// After the gate, finds close neighbors, syncs with each in
    /// round-robin batches, admits returned hints into the verification
    /// pipeline, and tracks discovered keys for bootstrap drain detection.
    #[allow(clippy::too_many_lines)]
    fn start_bootstrap_sync(
        &mut self,
        dht_events: tokio::sync::broadcast::Receiver<DhtNetworkEvent>,
    ) {
        let p2p = Arc::clone(&self.p2p_node);
        let storage = Arc::clone(&self.storage);
        let paid_list = Arc::clone(&self.paid_list);
        let queues = Arc::clone(&self.queues);
        let config = Arc::clone(&self.config);
        let shutdown = self.shutdown.clone();
        let is_bootstrapping = Arc::clone(&self.is_bootstrapping);
        let bootstrap_state = Arc::clone(&self.bootstrap_state);
        let bootstrap_complete_notify = Arc::clone(&self.bootstrap_complete_notify);
        let sync_cycle_epoch = Arc::clone(&self.sync_cycle_epoch);
        let repair_proofs = Arc::clone(&self.repair_proofs);
        let my_commitment_state = Arc::clone(&self.commitment_state);
        let last_commitment_by_peer = Arc::clone(&self.last_commitment_by_peer);
        let ever_capable_peers = Arc::clone(&self.ever_capable_peers);
        let sig_verify_attempts = Arc::clone(&self.sig_verify_attempts);

        let handle = tokio::spawn(async move {
            // Wait for DHT bootstrap to complete before snapshotting
            // neighbors. The routing table is empty until saorsa-core
            // finishes its FIND_NODE rounds and bucket refreshes.
            let gate = bootstrap::wait_for_bootstrap_complete(
                dht_events,
                config.bootstrap_complete_timeout_secs,
                &shutdown,
            )
            .await;

            if gate == bootstrap::BootstrapGateResult::Shutdown {
                return;
            }

            let self_id = *p2p.peer_id();
            let neighbors =
                neighbor_sync::snapshot_close_neighbors(&p2p, &self_id, config.neighbor_sync_scope)
                    .await;

            if neighbors.is_empty() {
                info!("Bootstrap sync: no close neighbors found, marking drained");
                bootstrap::mark_bootstrap_drained(&bootstrap_state).await;
                complete_bootstrap(&is_bootstrapping, &bootstrap_complete_notify).await;
                return;
            }

            let neighbor_count = neighbors.len();
            info!("Bootstrap sync: syncing with {neighbor_count} close neighbors");

            // Process neighbors in batches of NEIGHBOR_SYNC_PEER_COUNT.
            for batch in neighbors.chunks(config.neighbor_sync_peer_count) {
                if shutdown.is_cancelled() {
                    break;
                }

                let mut hints_by_peer = neighbor_sync::build_sync_hints_for_peers(
                    batch,
                    &storage,
                    &paid_list,
                    &p2p,
                    config.close_group_size,
                    config.paid_list_close_group_size,
                )
                .await;

                for peer in batch {
                    if shutdown.is_cancelled() {
                        break;
                    }

                    // Re-read on each iteration so peers see current state.
                    let bootstrapping = *is_bootstrapping.read().await;

                    bootstrap::increment_pending_requests(&bootstrap_state, 1).await;

                    let hints = hints_by_peer.remove(peer).unwrap_or_default();
                    let outcome = neighbor_sync::sync_with_peer_with_hints(
                        peer,
                        &p2p,
                        &config,
                        bootstrapping,
                        hints,
                        // Atomically snapshot + mark-gossiped: emitted in the
                        // bootstrap-sync request, so we stay answerable for it
                        // (ADR-0002). One critical section avoids a TOCTOU where a
                        // concurrent retire/rotate drops the slot between read and
                        // mark.
                        my_commitment_state
                            .current_for_gossip()
                            .map(|b| b.commitment().clone()),
                    )
                    .await;

                    bootstrap::decrement_pending_requests(&bootstrap_state, 1).await;

                    if let Some(outcome) = outcome {
                        // Ingest the peer's piggybacked commitment from the
                        // response (same verification as the request path).
                        // Bootstrap is the FIRST gossip we receive from most
                        // peers, so this populates last_commitment_by_peer.
                        //
                        // We intentionally do NOT trigger a gossip-audit here:
                        // during bootstrap this node may itself still be
                        // bootstrapping (audits are gated on that), and the
                        // close-group/RT view is not yet stable. The peer is
                        // audited on the first STEADY-STATE neighbor-sync round
                        // after bootstrap drains (request + response paths both
                        // trigger), which is within one sync cycle — so caching
                        // the commitment here is sufficient and there is no
                        // coverage gap (ADR-0002).
                        ingest_peer_commitment(
                            peer,
                            outcome.response.commitment.as_ref(),
                            &p2p,
                            &last_commitment_by_peer,
                            &ever_capable_peers,
                            &sig_verify_attempts,
                        )
                        .await; // sig_verify_attempts in scope from line ~1080

                        if !outcome.response.bootstrapping {
                            record_sent_replica_hints(
                                peer,
                                &outcome.sent_replica_hints,
                                &repair_proofs,
                                &sync_cycle_epoch,
                            )
                            .await;
                            // Admit hints into verification pipeline.
                            let outcome = admit_and_queue_hints(
                                &self_id,
                                peer,
                                &outcome.response.replica_hints,
                                &outcome.response.paid_hints,
                                &p2p,
                                &config,
                                &storage,
                                &paid_list,
                                &queues,
                            )
                            .await;

                            // Track discovered keys for drain detection.
                            if !outcome.discovered.is_empty() {
                                bootstrap::track_discovered_keys(
                                    &bootstrap_state,
                                    &outcome.discovered,
                                )
                                .await;
                            }

                            // Record / retire capacity rejections so the
                            // drain check correctly reflects whether each
                            // source still owes us re-hinted work after
                            // queue overflow.
                            if outcome.capacity_rejected_count > 0 {
                                bootstrap::note_capacity_rejected(&bootstrap_state, *peer).await;
                            } else {
                                bootstrap::clear_capacity_rejected(&bootstrap_state, peer).await;
                            }
                        }
                    }
                }
            }

            // Check drain condition.
            {
                let q = queues.read().await;
                if bootstrap::check_bootstrap_drained(&bootstrap_state, &q).await {
                    complete_bootstrap(&is_bootstrapping, &bootstrap_complete_notify).await;
                }
            }

            info!("Bootstrap sync completed");
        });
        self.task_handles.push(handle);
    }
}

// ===========================================================================
// Free functions for background tasks
// ===========================================================================

/// Which ceiling rejected an audit-responder admission attempt.
///
/// Stable, machine-readable so a production log-scrape can bucket drops by
/// cause. A 24 h node log collapsed 117 dropped responsible replies into a
/// single opaque "capacity reached" line; this splits the two distinct causes
/// so the next such investigation can tell a global-pool exhaustion (the whole
/// node is saturated) from a per-peer cap hit (one source is self-throttling)
/// without re-instrumenting.
///
/// This branch runs a SINGLE shared audit-responder pool for all challenge
/// kinds (responsible / subtree / byte), so there is no separate slow/fast
/// pool to distinguish here — the `kind=` log field already separates the
/// responsible (fast-path) challenge from the heavier subtree/byte ones. If a
/// dedicated slow pool is later split out, add its variants here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditResponderRejectReason {
    /// The global [`MAX_CONCURRENT_AUDIT_RESPONSES`] semaphore had no permit
    /// free; the per-peer cap was not the binding constraint.
    GlobalPoolFull,
    /// `source` already held its [`MAX_AUDIT_RESPONSES_PER_PEER`] in-flight
    /// share, so the global permit was never attempted.
    PerPeerCapFull,
}

impl AuditResponderRejectReason {
    /// Stable token emitted as `reason=<token>` in drop logs. Keep these values
    /// frozen — production log tooling greps for them.
    fn as_str(self) -> &'static str {
        match self {
            Self::GlobalPoolFull => "global_pool_full",
            Self::PerPeerCapFull => "per_peer_cap_full",
        }
    }
}

/// Why an audit-responder admission attempt failed, with the decision-time
/// capacity counters that let a drop be logged with full context.
///
/// `global_inflight`/`peer_inflight` are best-effort snapshots taken as the
/// decision was made (the two ceilings are read under different locks, so they
/// are not a single atomic view), but they are exact enough to tell a saturated
/// node from a single self-throttling flooder.
#[derive(Debug, Clone, Copy)]
struct AuditResponderAdmissionFailure {
    reason: AuditResponderRejectReason,
    /// Global permits in use across the whole engine at decision time.
    global_inflight: usize,
    /// Configured global ceiling ([`MAX_CONCURRENT_AUDIT_RESPONSES`]).
    global_limit: usize,
    /// In-flight audit responders already held for `source` at decision time.
    peer_inflight: u32,
    /// Configured per-peer ceiling ([`MAX_AUDIT_RESPONSES_PER_PEER`]).
    peer_limit: u32,
}

impl fmt::Display for AuditResponderAdmissionFailure {
    /// Renders the stable `reason=... global_inflight=... global_limit=...
    /// peer_inflight=... peer_limit=...` suffix appended to every drop log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "reason={} global_inflight={} global_limit={} peer_inflight={} peer_limit={}",
            self.reason.as_str(),
            self.global_inflight,
            self.global_limit,
            self.peer_inflight,
            self.peer_limit,
        )
    }
}

/// RAII admission for one audit-responder task: holds the GLOBAL permit and,
/// on drop, decrements the PER-PEER in-flight count. Moving this into the
/// spawned task ties both bounds to the task's exact lifetime — no manual
/// decrement to forget on an early return or panic.
struct AuditResponderGuard {
    _permit: tokio::sync::OwnedSemaphorePermit,
    inflight: Arc<RwLock<HashMap<PeerId, u32>>>,
    peer: PeerId,
}

impl Drop for AuditResponderGuard {
    fn drop(&mut self) {
        // Decrement (and prune to keep the map bounded) without blocking the
        // async runtime: a short lock on a tiny map.
        //
        // Fast path: if the (uncontended, tiny) lock is free, decrement inline
        // with no spawn. Otherwise defer to a task — but only if a runtime is
        // actually current, so `Drop` during shutdown (no runtime) can never
        // panic. A missed decrement at shutdown is harmless: the whole map is
        // being dropped with the engine.
        let peer = self.peer;
        if let Ok(mut map) = self.inflight.try_write() {
            if let Some(n) = map.get_mut(&peer) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    map.remove(&peer);
                }
            }
            return;
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let inflight = Arc::clone(&self.inflight);
            handle.spawn(async move {
                let mut map = inflight.write().await;
                if let Some(n) = map.get_mut(&peer) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        map.remove(&peer);
                    }
                }
            });
        }
    }
}

/// A live round-1 → round-2 subtree-audit session: proof of a matching round 1.
struct SubtreeSession {
    commitment_hash: [u8; 32],
    nonce: [u8; 32],
    inserted: Instant,
}

/// Responder-wide token bucket over the chunk bytes round-1 proof building may
/// read and hash, refilled continuously at
/// [`SUBTREE_ROUND1_WORK_REFILL_BYTES_PER_SEC`] up to
/// [`SUBTREE_ROUND1_WORK_BURST_BYTES`].
///
/// Deliberately keyed by nothing. The per-peer cooldown limits how often one
/// identity may ask, so it is refilled by acquiring more identities; this is
/// charged for work done regardless of who asked, so it is not.
///
/// Charged after the fact, with the bytes the proof actually covered: the cost
/// of a request is not known until the pinned commitment has been resolved and
/// its subtree selected, both of which happen inside the handler. Admission
/// therefore asks only whether the balance is positive, and a proof that costs
/// more than is left drives the balance NEGATIVE rather than stopping at zero.
/// Carrying the debt is what makes the bound real: without it a maximal proof
/// would cost the same as a trivial one, since either way the next request only
/// has to wait for the balance to climb back above zero. With it, sustained
/// throughput settles at refill ÷ cost-per-proof, so expensive proofs are
/// admitted proportionally less often.
struct Round1WorkBudget {
    /// Signed, so an over-large proof leaves debt to work off.
    balance: i64,
    last_refill: Instant,
}

impl Round1WorkBudget {
    /// Deepest debt carried, so one huge proof cannot lock out honest audits
    /// for longer than the burst takes to refill.
    const MAX_DEBT: i64 = -SUBTREE_ROUND1_WORK_BURST_BYTES;
    /// Nanoseconds per second, for the sub-second part of a refill.
    const NANOS_PER_SEC: i64 = 1_000_000_000;

    fn new() -> Self {
        Self {
            balance: SUBTREE_ROUND1_WORK_BURST_BYTES,
            last_refill: Instant::now(),
        }
    }

    /// Add the tokens accrued since the last touch, capped at the burst size.
    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_refill);
        self.last_refill = now;
        let whole_secs = i64::try_from(elapsed.as_secs())
            .unwrap_or(i64::MAX)
            .saturating_mul(SUBTREE_ROUND1_WORK_REFILL_BYTES_PER_SEC);
        let sub_sec = i64::from(elapsed.subsec_nanos())
            .saturating_mul(SUBTREE_ROUND1_WORK_REFILL_BYTES_PER_SEC)
            / Self::NANOS_PER_SEC;
        self.balance = self
            .balance
            .saturating_add(whole_secs.saturating_add(sub_sec))
            .min(SUBTREE_ROUND1_WORK_BURST_BYTES);
    }

    /// Whether budget remains for a new round-1 proof.
    fn has_budget(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.balance > 0
    }

    /// Charge `bytes` of completed proof work, carrying debt down to
    /// [`Self::MAX_DEBT`].
    fn charge(&mut self, bytes: i64, now: Instant) {
        self.refill(now);
        self.balance = self.balance.saturating_sub(bytes).max(Self::MAX_DEBT);
    }
}

/// Resource controls for the HEAVY subtree-audit round 1: a tight
/// admission pool separate from the light responsible/slice audits, a per-peer
/// rate cooldown, and single-use round-1 → round-2 sessions so a round-2 slice
/// challenge is only served after a matching round 1.
///
/// It also holds the responder-wide [`Round1WorkBudget`], the only one of those
/// bounds not keyed by peer identity, and so the only one that bounds sustained
/// work rather than concurrency or per-identity frequency.
#[derive(Clone)]
struct SubtreeRound1Limiter {
    semaphore: Arc<Semaphore>,
    inflight: Arc<RwLock<HashMap<PeerId, u32>>>,
    cooldown: Arc<RwLock<HashMap<PeerId, Instant>>>,
    /// Per-peer minimum spacing between served round-1 proofs (config-driven;
    /// [`SUBTREE_ROUND1_RESPONDER_COOLDOWN`] in production, near-zero in tests).
    cooldown_interval: Duration,
    sessions: Arc<RwLock<HashMap<(PeerId, u64), SubtreeSession>>>,
    /// Identity-independent ceiling on sustained round-1 work.
    work: Arc<RwLock<Round1WorkBudget>>,
}

impl SubtreeRound1Limiter {
    fn new(cooldown_interval: Duration) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_SUBTREE_ROUND1)),
            inflight: Arc::new(RwLock::new(HashMap::new())),
            cooldown: Arc::new(RwLock::new(HashMap::new())),
            cooldown_interval,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            work: Arc::new(RwLock::new(Round1WorkBudget::new())),
        }
    }

    /// Charge completed round-1 proof work against the responder-wide budget.
    async fn charge_work(&self, content_bytes: i64) {
        self.work
            .write()
            .await
            .charge(content_bytes, Instant::now());
    }

    /// Admit one heavy round-1 proof for `source`: take a concurrency permit
    /// FIRST (so a full pool never wastes the peer's cooldown allowance), then
    /// the responder-wide work budget, then the per-peer rate cooldown. `None`
    /// drops the challenge (the remote auditor applies its own graced-timeout
    /// policy).
    async fn admit(&self, source: &PeerId) -> Option<AuditResponderGuard> {
        let guard = admit_audit_responder_with_limits(
            &self.semaphore,
            &self.inflight,
            source,
            MAX_CONCURRENT_SUBTREE_ROUND1,
            MAX_SUBTREE_ROUND1_PER_PEER,
        )
        .await
        .ok()?;
        // Checked before the per-peer cooldown is stamped, so a peer refused for
        // want of budget is not also charged its next allowance.
        if !self.work.write().await.has_budget(Instant::now()) {
            return None; // guard drops here, releasing the permit + slot
        }
        let now = Instant::now();
        let mut cooldown = self.cooldown.write().await;
        if let Some(&last) = cooldown.get(source) {
            if now.duration_since(last) < self.cooldown_interval {
                return None; // guard drops here, releasing the permit + slot
            }
        }
        // Evict lapsed entries (their cooldown has expired, so they no longer
        // limit) and cap capacity, so peer-id churn can't grow this map unbounded.
        cooldown.retain(|_, &mut last| now.duration_since(last) < self.cooldown_interval);
        if cooldown.len() >= MAX_SUBTREE_SESSIONS {
            if let Some(oldest) = cooldown.iter().min_by_key(|(_, &t)| t).map(|(k, _)| *k) {
                cooldown.remove(&oldest);
            }
        }
        cooldown.insert(*source, now);
        Some(guard)
    }

    /// Record a single-use session once a round-1 proof is built and about to be
    /// sent, so the matching round 2 is admitted exactly once.
    async fn open_session(
        &self,
        source: PeerId,
        challenge_id: u64,
        commitment_hash: [u8; 32],
        nonce: [u8; 32],
    ) {
        let now = Instant::now();
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, e| now.duration_since(e.inserted) < SUBTREE_SESSION_TTL);
        if sessions.len() >= MAX_SUBTREE_SESSIONS {
            if let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, e)| e.inserted)
                .map(|(k, _)| *k)
            {
                sessions.remove(&oldest);
            }
        }
        sessions.insert(
            (source, challenge_id),
            SubtreeSession {
                commitment_hash,
                nonce,
                inserted: now,
            },
        );
    }

    /// Atomically consume the round-2 session for this exchange. `true` iff a
    /// live session matching `(source, challenge_id, commitment_hash, nonce)`
    /// existed (and is now removed); a miss silently drops round 2 to the graced
    /// timeout lane (sessions are ephemeral and can be lost across a restart).
    async fn consume_session(
        &self,
        source: &PeerId,
        challenge_id: u64,
        commitment_hash: &[u8; 32],
        nonce: &[u8; 32],
    ) -> bool {
        let mut sessions = self.sessions.write().await;
        let matches = sessions.get(&(*source, challenge_id)).is_some_and(|e| {
            Instant::now().duration_since(e.inserted) < SUBTREE_SESSION_TTL
                && &e.commitment_hash == commitment_hash
                && &e.nonce == nonce
        });
        if matches {
            sessions.remove(&(*source, challenge_id));
        }
        matches
    }
}

/// Outcome of admitting a round-2 slice challenge.
enum SliceAdmission {
    /// Admitted: the guard holds the global permit and the per-peer slot, and
    /// the single-use round-1 session has been consumed.
    Admitted(AuditResponderGuard),
    /// Refused at a responder ceiling. The round-1 session is left INTACT.
    Capacity(AuditResponderAdmissionFailure),
    /// No live round-1 session matched this challenge.
    NoSession,
}

/// Admit a round-2 slice challenge: take the responder permit BEFORE consuming
/// the single-use round-1 session.
///
/// The order is the point: a single-use token must not be spent on work that is
/// then refused. Consuming first and testing admission second leaves the session
/// destroyed by a purely local capacity drop, so the refusal is not recoverable
/// even in principle.
///
/// Scope of the benefit today, stated honestly: `request_slice_proof` issues one
/// `send_request` and maps any failure straight to `SliceRound::Timeout`, so the
/// auditor does not currently re-send round 2 within an audit. The preserved
/// session is therefore not yet *recovering* an audit — it keeps a refusal
/// truthful (temporary means temporary) and keeps the invariant available for a
/// retry, rather than baking "capacity drop is permanent" into the state
/// machine. If an application-level retry is ruled out for good, this ordering
/// still costs nothing over the alternative.
///
/// Cost of the ordering: the permit and per-peer slot are held across the
/// session probe, which is one in-memory map lookup and no chunk work. The
/// per-peer cap still bounds a peer sending unsessioned challenges to the same
/// share it could already occupy with well-formed ones, so the admission
/// surface is unchanged.
async fn admit_slice_challenge(
    semaphore: &Arc<Semaphore>,
    inflight: &Arc<RwLock<HashMap<PeerId, u32>>>,
    round1: &SubtreeRound1Limiter,
    source: &PeerId,
    challenge: &protocol::SubtreeSliceChallenge,
) -> SliceAdmission {
    let guard = match admit_audit_responder(semaphore, inflight, source).await {
        Ok(guard) => guard,
        Err(failure) => return SliceAdmission::Capacity(failure),
    };
    if !round1
        .consume_session(
            source,
            challenge.challenge_id,
            &challenge.expected_commitment_hash,
            &challenge.nonce,
        )
        .await
    {
        // Release the permit and per-peer slot before the caller replies: no
        // chunk work follows, so holding them would shrink the pool for nothing.
        drop(guard);
        return SliceAdmission::NoSession;
    }
    SliceAdmission::Admitted(guard)
}

/// Try to admit one audit-responder task for `source`: take a global permit AND
/// a per-peer slot (both bounded). Returns `Err` with the binding ceiling and
/// its decision-time counters (caller drops the challenge, leaving the remote
/// auditor to apply that audit path's timeout policy) if either ceiling is hit,
/// so one flooder can neither exhaust the global pool's effect on others nor
/// exceed its own per-peer share (codex-r2 A). The `Err` reason lets the caller
/// log exactly WHY the drop happened rather than a single opaque "capacity
/// reached".
async fn admit_audit_responder(
    semaphore: &Arc<Semaphore>,
    inflight: &Arc<RwLock<HashMap<PeerId, u32>>>,
    source: &PeerId,
) -> std::result::Result<AuditResponderGuard, AuditResponderAdmissionFailure> {
    admit_audit_responder_with_limits(
        semaphore,
        inflight,
        source,
        MAX_CONCURRENT_AUDIT_RESPONSES,
        MAX_AUDIT_RESPONSES_PER_PEER,
    )
    .await
}

/// Admission core shared by the light audit pool ([`admit_audit_responder`]) and
/// the tight heavy subtree round-1 pool: take a global permit AND a per-peer slot
/// under the given limits.
async fn admit_audit_responder_with_limits(
    semaphore: &Arc<Semaphore>,
    inflight: &Arc<RwLock<HashMap<PeerId, u32>>>,
    source: &PeerId,
    global_limit: usize,
    peer_limit: u32,
) -> std::result::Result<AuditResponderGuard, AuditResponderAdmissionFailure> {
    // `available_permits()` is a cheap atomic load; `global_limit - available`
    // is the best-effort in-flight count at decision time. Not synchronized with
    // the per-peer lock, so it is a snapshot, not a single atomic view.
    let global_inflight = |sem: &Semaphore| global_limit.saturating_sub(sem.available_permits());

    // Per-peer cap first (cheap, and the fairness-critical bound), committed
    // under the write lock so concurrent challenges from the same peer can't
    // both slip past the cap.
    {
        let mut map = inflight.write().await;
        let entry = map.entry(*source).or_insert(0);
        if *entry >= peer_limit {
            let peer_inflight = *entry;
            drop(map); // release before the (unrelated) semaphore read
            return Err(AuditResponderAdmissionFailure {
                reason: AuditResponderRejectReason::PerPeerCapFull,
                global_inflight: global_inflight(semaphore),
                global_limit,
                peer_inflight,
                peer_limit,
            });
        }
        *entry += 1;
    }
    // Then the global ceiling. If it's exhausted, give back the per-peer slot we
    // just claimed so it isn't leaked.
    let Ok(permit) = Arc::clone(semaphore).try_acquire_owned() else {
        let peer_inflight = {
            let mut map = inflight.write().await;
            map.remove(source).map_or(0, |n| {
                // Report the per-peer occupancy AFTER releasing our rolled-back
                // slot: the share still held by this source's other in-flight
                // tasks (below the cap, since the per-peer check passed).
                let remaining = n.saturating_sub(1);
                if remaining > 0 {
                    map.insert(*source, remaining);
                }
                remaining
            })
        };
        return Err(AuditResponderAdmissionFailure {
            reason: AuditResponderRejectReason::GlobalPoolFull,
            global_inflight: global_inflight(semaphore),
            global_limit,
            peer_inflight,
            peer_limit,
        });
    };
    Ok(AuditResponderGuard {
        _permit: permit,
        inflight: Arc::clone(inflight),
        peer: *source,
    })
}

/// Handle an incoming replication protocol message.
///
/// When `rr_message_id` is `Some`, the request arrived via the `/rr/`
/// request-response path and the response must be sent via `send_response`
/// so saorsa-core can route it back to the waiting `send_request` caller.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn handle_replication_message(
    source: &PeerId,
    data: &[u8],
    inbound_protocol: &str,
    p2p_node: &Arc<P2PNode>,
    storage: &Arc<LmdbStorage>,
    paid_list: &Arc<PaidList>,
    payment_verifier: &Arc<PaymentVerifier>,
    queues: &Arc<RwLock<ReplicationQueues>>,
    config: &ReplicationConfig,
    is_bootstrapping: &Arc<RwLock<bool>>,
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    sync_history: &Arc<RwLock<HashMap<PeerId, PeerSyncRecord>>>,
    sync_cycle_epoch: &Arc<RwLock<u64>>,
    repair_proofs: &Arc<RwLock<RepairProofs>>,
    last_commitment_by_peer: &Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>>,
    ever_capable_peers: &Arc<RwLock<HashSet<PeerId>>>,
    sig_verify_attempts: &Arc<RwLock<HashMap<PeerId, Instant>>>,
    my_commitment_state: &Arc<ResponderCommitmentState>,
    gossip_audit: &GossipAuditTrigger,
    audit_responder_semaphore: &Arc<Semaphore>,
    audit_responder_inflight: &Arc<RwLock<HashMap<PeerId, u32>>>,
    subtree_round1: &SubtreeRound1Limiter,
    rr_message_id: Option<&str>,
) -> Result<()> {
    // Size guard BEFORE decoding, keyed on the BODY's family — not on the id the
    // message arrived on.
    //
    // Every later check — protocol family, live round-1 session, responder
    // admission — reads fields of the decoded body, so none of them can run
    // first. Decoding is therefore the first thing an unknown peer can make this
    // node do, and the audit bodies carry variable-length collections, so under
    // the 10 MiB core ceiling a sessionless peer could force multi-megabyte
    // allocation and decode work per message with nothing spent on its side.
    // Audit bodies are ~110 KiB at worst (see `MAX_AUDIT_MESSAGE_SIZE`), so a
    // tighter family ceiling costs honest traffic nothing.
    //
    // Selecting that ceiling from `inbound_protocol` did NOT close the path it
    // claimed to: an audit body addressed to the CORE id skipped the audit
    // ceiling entirely, was decoded under the 10 MiB allowance, and only then
    // dropped by `body_matches_protocol` — after its collections had been
    // allocated. A `SubtreeSliceChallenge` carrying 200,000 openings encodes to
    // ~6.6 MB and sailed through. The ceiling has to follow the body, and the
    // body's discriminant is readable from the first few bytes without decoding
    // anything attacker-sized, so it can be read first.
    //
    // A prefix too malformed to classify gets the strict ceiling: a message we
    // cannot classify is not one to decode generously.
    let peeked_family = protocol::peek_variant_index(data).map(protocol::family_of_variant);
    let is_audit_body = peeked_family.map_or(true, protocol::BodyFamily::is_audit);
    if is_audit_body && data.len() > MAX_AUDIT_MESSAGE_SIZE {
        debug!(
            "Dropping oversized audit-family message from {source} on {inbound_protocol}: \
             {} bytes > {MAX_AUDIT_MESSAGE_SIZE}",
            data.len()
        );
        return Ok(());
    }

    let msg = ReplicationMessage::decode(data)
        .map_err(|e| Error::Protocol(format!("Failed to decode replication message: {e}")))?;

    // Symmetric id/body guard: subtree-audit bodies are valid ONLY on the audit
    // id, and core bodies ONLY on the core id. postcard::from_bytes ignores
    // trailing bytes, so a mixed-version peer's message could otherwise decode
    // into a valid-looking but wrong body (e.g. an old round-1 `Proof` on the
    // core id misreading its bytes as the new `content_len`/`nonced_root`). The
    // outer enum discriminants are unchanged across versions, so this drop by
    // (id, is_subtree_audit) is exact.
    if !body_matches_protocol(&msg.body, inbound_protocol) {
        debug!(
            "Dropping replication body (variant {}) on protocol {inbound_protocol}: \
             wrong id for its family (cross-version or misrouted)",
            msg.body.variant_index()
        );
        return Ok(());
    }

    match msg.body {
        ReplicationMessageBody::FreshReplicationOffer(ref offer) => {
            handle_fresh_offer(
                source,
                offer,
                storage,
                paid_list,
                payment_verifier,
                p2p_node,
                config,
                msg.request_id,
                rr_message_id,
            )
            .await
        }
        ReplicationMessageBody::PaidNotify(ref notify) => {
            handle_paid_notify(
                source,
                notify,
                paid_list,
                payment_verifier,
                p2p_node,
                config,
            )
            .await
        }
        ReplicationMessageBody::NeighborSyncRequest(ref request) => {
            let bootstrapping = *is_bootstrapping.read().await;
            // Phase-3 storage-bound audit: store the sender's
            // commitment for use as `expected_commitment_hash` in
            // future audits. Verify signature before storing so a peer
            // cannot inject a forged commitment for someone else.
            if let Some(target) = ingest_peer_commitment(
                source,
                request.commitment.as_ref(),
                p2p_node,
                last_commitment_by_peer,
                ever_capable_peers,
                sig_verify_attempts,
            )
            .await
            {
                maybe_trigger_gossip_audit(gossip_audit, source, target).await;
            }
            handle_neighbor_sync_request(
                source,
                request,
                p2p_node,
                storage,
                paid_list,
                queues,
                config,
                bootstrapping,
                bootstrap_state,
                sync_history,
                sync_cycle_epoch,
                repair_proofs,
                // Atomically snapshot + mark-gossiped: emitted in the sync
                // response, so we must stay answerable for it (ADR-0002).
                my_commitment_state
                    .current_for_gossip()
                    .map(|b| b.commitment().clone()),
                msg.request_id,
                rr_message_id,
            )
            .await
        }
        ReplicationMessageBody::VerificationRequest(ref request) => {
            handle_verification_request(
                source,
                request,
                storage,
                paid_list,
                p2p_node,
                msg.request_id,
                rr_message_id,
            )
            .await
        }
        ReplicationMessageBody::FetchRequest(ref request) => {
            handle_fetch_request(
                source,
                request,
                storage,
                p2p_node,
                msg.request_id,
                rr_message_id,
            )
            .await
        }
        ReplicationMessageBody::AuditChallenge(challenge) => {
            // Responsible-chunk audit (audit #2) responder: answer with per-key
            // possession digests. This same handler also answers the
            // prune-confirmation audit, which sends the same `AuditChallenge`
            // wire message.
            //
            // Answering digests the stored bytes of every challenged key, so —
            // like the subtree/byte audits below — run it on a detached task off
            // this serial message loop. Handling it inline lets one challenge
            // block all other replication traffic until its digests complete
            // (head-of-line blocking). The same flood-fair admission applies: a
            // global ceiling AND a per-peer cap, dropping the challenge if either
            // is hit. A dropped challenge reads as a timeout to the auditor, and
            // once the rollout gate is removed that is penalised again by the
            // caller, so the caps must remain high enough for honest audit load;
            // the per-peer share still prevents one flooder from starving others.
            let guard = match admit_audit_responder(
                audit_responder_semaphore,
                audit_responder_inflight,
                source,
            )
            .await
            {
                Ok(guard) => guard,
                Err(failure) => {
                    protocol::record_audit_drop(protocol::AuditDropKind::Responsible);
                    warn!(
                        "Audit challenge reply not sent: kind=responsible response=dropped \
                         source={source} {failure}"
                    );
                    return Ok(());
                }
            };
            let bootstrapping = *is_bootstrapping.read().await;
            let storage = Arc::clone(storage);
            let p2p_node = Arc::clone(p2p_node);
            let source = *source;
            let request_id = msg.request_id;
            let rr_message_id = rr_message_id.map(ToOwned::to_owned);
            tokio::spawn(async move {
                let _guard = guard; // global permit + per-peer slot, held until done
                if let Err(e) = handle_audit_challenge_msg(
                    &source,
                    &challenge,
                    &storage,
                    &p2p_node,
                    bootstrapping,
                    request_id,
                    rr_message_id.as_deref(),
                )
                .await
                {
                    debug!("Audit challenge from {source} error: {e}");
                }
            });
            Ok(())
        }
        ReplicationMessageBody::SubtreeAuditChallenge(challenge) => {
            // Gossip-triggered storage-bound subtree audit (ADR-0002). The
            // responder rebuilds the WHOLE nonce-selected subtree, reading every
            // leaf's bytes from disk (`get_raw` × ~sqrt(N) leaves). Run it on a
            // detached task so this serial message loop is never blocked on disk
            // I/O — otherwise one audit stalls all replication traffic (§5).
            //
            // A bounded, flood-fair admission restores backpressure (codex#1 +
            // codex-r2 A): a global ceiling AND a per-peer cap. If either is hit
            // we drop this challenge. Subtree auditors grace timeout
            // non-responses, so capacity drops throttle flooders without turning
            // into trust penalties (and one source cannot starve other peers,
            // since its share is capped per-peer).
            info!(
                "Audit challenge received: kind=subtree source={source} request_response={}",
                rr_message_id.is_some(),
            );
            // Round 1 is the HEAVY path (rebuilds + hashes the whole sqrt-subtree),
            // so it uses its own tight admission pool + per-peer rate cooldown,
            // separate from the light responsible/slice audits, and a miss silently
            // drops (subtree auditors grace timeouts).
            let Some(guard) = subtree_round1.admit(source).await else {
                protocol::record_audit_drop(protocol::AuditDropKind::Subtree);
                warn!(
                    "Audit challenge reply not sent: kind=subtree response=dropped \
                     source={source} (heavy round-1 pool full or per-peer cooldown)"
                );
                return Ok(());
            };
            let bootstrapping = *is_bootstrapping.read().await;
            let storage = Arc::clone(storage);
            let p2p_node = Arc::clone(p2p_node);
            let my_commitment_state = Arc::clone(my_commitment_state);
            let subtree_round1 = subtree_round1.clone();
            let source = *source;
            let request_id = msg.request_id;
            let rr_message_id = rr_message_id.map(ToOwned::to_owned);
            tokio::spawn(async move {
                let _guard = guard; // heavy permit + per-peer slot, held until done
                let storage_commitment_audit::Round1Work {
                    response,
                    content_bytes,
                } = storage_commitment_audit::handle_subtree_challenge_measured(
                    &challenge,
                    &storage,
                    p2p_node.peer_id(),
                    bootstrapping,
                    Some(&my_commitment_state),
                )
                .await;
                // Charge the work actually done, on EVERY outcome.
                //
                // This used to charge only the `Proof` arm, reasoning that the
                // rejecting paths either read nothing or reflected this node's
                // own broken storage. The second half of that was wrong: a
                // retained commitment containing one unreadable key still costs
                // a full run of reads and keyed-BLAKE3 passes over every leaf
                // before it, and then rejects. An attacker who finds such a
                // commitment could replay subtrees over it indefinitely for
                // free. The per-peer cooldown does not catch that either, since
                // it is escapable by rotating identity — the responder-wide
                // budget is the only bound that applies, so it has to see the
                // work. A zero charge is a no-op, so the untouched paths are
                // unaffected.
                subtree_round1.charge_work(content_bytes).await;
                // A round-1 proof authorizes exactly one matching round 2: open a
                // single-use session so a slice challenge cannot be served without
                // a live round-1 exchange.
                if let crate::replication::protocol::SubtreeAuditResponse::Proof { .. } = &response
                {
                    subtree_round1
                        .open_session(
                            source,
                            challenge.challenge_id,
                            challenge.expected_commitment_hash,
                            challenge.nonce,
                        )
                        .await;
                }
                let response_kind = subtree_audit_response_kind(&response);
                let sent = send_replication_response_checked(
                    &source,
                    &p2p_node,
                    request_id,
                    ReplicationMessageBody::SubtreeAuditResponse(response),
                    rr_message_id.as_deref(),
                )
                .await;
                if sent {
                    info!(
                        "Audit challenge reply sent: kind=subtree response={response_kind} \
                         source={source} request_response={}",
                        rr_message_id.is_some(),
                    );
                } else {
                    warn!(
                        "Audit challenge reply not sent: kind=subtree response={response_kind} \
                         source={source} request_response={}",
                        rr_message_id.is_some(),
                    );
                }
            });
            Ok(())
        }
        ReplicationMessageBody::SubtreeSliceChallenge(challenge) => {
            // Round 2 of the storage audit (ADR-0002 / V2-685): open one 1 KiB
            // block of each of the auditor's spot-check keys with a Bao verified
            // slice + nonced block-tree opening, or signal `Absent` for a
            // committed key we can no longer produce. Reads chunk bytes from disk
            // to build the proofs, so likewise spawned off the serial loop
            // under the same flood-fair admission (a global ceiling plus a
            // per-peer cap).
            info!(
                "Audit challenge received: kind=slice source={source} request_response={}",
                rr_message_id.is_some(),
            );
            let guard = match admit_slice_challenge(
                audit_responder_semaphore,
                audit_responder_inflight,
                subtree_round1,
                source,
                &challenge,
            )
            .await
            {
                SliceAdmission::Admitted(guard) => guard,
                // Capacity drop: same silent-shed contract as the other two audit
                // handlers. The session is still live, so the auditor's retry once
                // load clears can still be served.
                SliceAdmission::Capacity(failure) => {
                    protocol::record_audit_drop(protocol::AuditDropKind::Slice);
                    warn!(
                        "Audit challenge reply not sent: kind=slice response=dropped \
                         source={source} {failure}"
                    );
                    return Ok(());
                }
                // No live round-1 session: reply with a cheap `Transient` rejection
                // rather than dropping silently. Sessions are ephemeral (an honest
                // responder that restarts between rounds loses its session), and an
                // unanswered `send_request` would make saorsa-core record a
                // transport trust failure against that honest responder — an
                // ongoing effect, not just a rollout-window one. A `Transient`
                // reply routes the auditor to the graced timeout lane (no trust
                // penalty; the responder re-earns pinned credit on the next audit)
                // and does no chunk work, so it is not a DoS lever.
                SliceAdmission::NoSession => {
                    protocol::record_audit_drop(protocol::AuditDropKind::Slice);
                    debug!(
                        "Slice challenge without a live round-1 session source={source} \
                         challenge_id={} → Transient reject",
                        challenge.challenge_id
                    );
                    send_replication_response_checked(
                        source,
                        p2p_node,
                        msg.request_id,
                        ReplicationMessageBody::SubtreeSliceResponse(
                            protocol::SubtreeSliceResponse::Rejected {
                                challenge_id: challenge.challenge_id,
                                kind: protocol::RejectKind::Transient,
                                reason: "no live round-1 session".to_string(),
                            },
                        ),
                        rr_message_id,
                    )
                    .await;
                    return Ok(());
                }
            };
            let bootstrapping = *is_bootstrapping.read().await;
            let storage = Arc::clone(storage);
            let p2p_node = Arc::clone(p2p_node);
            let my_commitment_state = Arc::clone(my_commitment_state);
            let source = *source;
            let request_id = msg.request_id;
            let rr_message_id = rr_message_id.map(ToOwned::to_owned);
            tokio::spawn(async move {
                let _guard = guard; // global permit + per-peer slot, held until done
                let response = storage_commitment_audit::handle_subtree_slice_challenge(
                    &challenge,
                    &storage,
                    p2p_node.peer_id(),
                    bootstrapping,
                    Some(&my_commitment_state),
                )
                .await;
                let response_kind = subtree_slice_response_kind(&response);
                let sent = send_replication_response_checked(
                    &source,
                    &p2p_node,
                    request_id,
                    ReplicationMessageBody::SubtreeSliceResponse(response),
                    rr_message_id.as_deref(),
                )
                .await;
                if sent {
                    info!(
                        "Audit challenge reply sent: kind=slice response={response_kind} \
                         source={source} request_response={}",
                        rr_message_id.is_some(),
                    );
                } else {
                    warn!(
                        "Audit challenge reply not sent: kind=slice response={response_kind} \
                         source={source} request_response={}",
                        rr_message_id.is_some(),
                    );
                }
            });
            Ok(())
        }
        ReplicationMessageBody::GetCommitmentByPin(ref request) => {
            // ADR-0004: answer a commitment-by-pin fetch from the retained set
            // only. `lookup_by_hash` is an allocation-light read over the
            // bounded slot set; it returns the live current commitment or any
            // still-answerable recently-gossiped/quoted one. A miss is reported
            // as `NotRetained` (graced, never confirmed) rather than an error,
            // so an aged-out pin can never brand an honest node.
            //
            // Reuse the audit-responder admission guard (global ceiling + per-peer
            // cap) so a flood of fetches cannot drive unbounded commitment
            // clone/encode/send work; over-limit is dropped, which the fetching
            // peer graces exactly like a missed audit response.
            let _guard = match admit_audit_responder(
                audit_responder_semaphore,
                audit_responder_inflight,
                source,
            )
            .await
            {
                Ok(guard) => guard,
                Err(failure) => {
                    debug!("GetCommitmentByPin from {source} dropped: {failure}");
                    return Ok(());
                }
            };
            let response = my_commitment_state.lookup_by_hash(&request.pin).map_or(
                protocol::GetCommitmentByPinResponse::NotRetained { pin: request.pin },
                |built| protocol::GetCommitmentByPinResponse::Found {
                    commitment: built.commitment().clone(),
                },
            );
            send_replication_response(
                source,
                p2p_node,
                msg.request_id,
                ReplicationMessageBody::GetCommitmentByPinResponse(response),
                rr_message_id,
            )
            .await;
            Ok(())
        }
        // Response messages are handled by their respective request initiators.
        ReplicationMessageBody::FreshReplicationResponse(_)
        | ReplicationMessageBody::NeighborSyncResponse(_)
        | ReplicationMessageBody::VerificationResponse(_)
        | ReplicationMessageBody::FetchResponse(_)
        | ReplicationMessageBody::AuditResponse(_)
        | ReplicationMessageBody::SubtreeAuditResponse(_)
        | ReplicationMessageBody::SubtreeSliceResponse(_)
        | ReplicationMessageBody::GetCommitmentByPinResponse(_) => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Per-message-type handlers
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn handle_fresh_offer(
    source: &PeerId,
    offer: &protocol::FreshReplicationOffer,
    storage: &Arc<LmdbStorage>,
    paid_list: &Arc<PaidList>,
    payment_verifier: &Arc<PaymentVerifier>,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    request_id: u64,
    rr_message_id: Option<&str>,
) -> Result<()> {
    let self_id = *p2p_node.peer_id();

    // Rule 5: reject if PoP is missing.
    if offer.proof_of_payment.is_empty() {
        send_replication_response(
            source,
            p2p_node,
            request_id,
            ReplicationMessageBody::FreshReplicationResponse(FreshReplicationResponse::Rejected {
                key: offer.key,
                reason: "Missing proof of payment".to_string(),
            }),
            rr_message_id,
        )
        .await;
        return Ok(());
    }

    // Enforce chunk size invariant: the normal PUT path rejects data larger
    // than MAX_CHUNK_SIZE; the replication receive path must do the same to
    // prevent peers from pushing oversized records through replication.
    if offer.data.len() > crate::ant_protocol::MAX_CHUNK_SIZE {
        warn!(
            "Rejecting fresh offer for key {}: data size {} exceeds MAX_CHUNK_SIZE {}",
            hex::encode(offer.key),
            offer.data.len(),
            crate::ant_protocol::MAX_CHUNK_SIZE,
        );
        p2p_node
            .report_trust_event(
                source,
                TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
            )
            .await;
        send_replication_response(
            source,
            p2p_node,
            request_id,
            ReplicationMessageBody::FreshReplicationResponse(FreshReplicationResponse::Rejected {
                key: offer.key,
                reason: format!(
                    "Data size {} exceeds maximum chunk size {}",
                    offer.data.len(),
                    crate::ant_protocol::MAX_CHUNK_SIZE,
                ),
            }),
            rr_message_id,
        )
        .await;
        return Ok(());
    }

    // Mirror the normal PUT path: the advertised key must be the content
    // address of the supplied bytes before any expensive payment verification.
    let computed_key = crate::client::compute_address(&offer.data);
    if computed_key != offer.key {
        warn!(
            "Rejecting fresh offer for key {}: content address mismatch, computed {}",
            hex::encode(offer.key),
            hex::encode(computed_key),
        );
        p2p_node
            .report_trust_event(
                source,
                TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
            )
            .await;
        send_replication_response(
            source,
            p2p_node,
            request_id,
            ReplicationMessageBody::FreshReplicationResponse(FreshReplicationResponse::Rejected {
                key: offer.key,
                reason: format!(
                    "Content address mismatch: expected {}, computed {}",
                    hex::encode(offer.key),
                    hex::encode(computed_key),
                ),
            }),
            rr_message_id,
        )
        .await;
        return Ok(());
    }

    // Rule 7: check storage admission. Fresh chunk receivers accept across the
    // paid-close-group neighbourhood (`paid_list_close_group_size`, = K_BUCKET_SIZE,
    // the same width client PUTs use), not just the close group plus a small
    // margin (ADR-0003). During full-node shunning a healthy replica's routing
    // table may still list closer full nodes it hasn't evicted yet, ranking it
    // outside the narrow window in its own view; the wider accept window absorbs
    // that transient skew so the chunk still lands. Retention (pruning) stays at
    // `storage_admission_width`, so steady-state replication is unchanged.
    if !admission::is_responsible(
        &self_id,
        &offer.key,
        p2p_node,
        config.paid_list_close_group_size,
    )
    .await
    {
        send_replication_response(
            source,
            p2p_node,
            request_id,
            ReplicationMessageBody::FreshReplicationResponse(FreshReplicationResponse::Rejected {
                key: offer.key,
                reason: "Not in storage-admission range for this key".to_string(),
            }),
            rr_message_id,
        )
        .await;
        return Ok(());
    }

    // Disk-space pre-check — mirror the PUT handler (V2-411). A full node can
    // never store this record, so reject it before the expensive payment
    // verification (EVM on-chain query / merkle pool work) rather than verifying
    // and only then failing at `storage.put` below. Reuses the cached capacity
    // check (passing results only, so freed space is detected promptly), and the
    // store path keeps its own check as defence-in-depth.
    if let Err(e) = storage.check_capacity() {
        info!(
            target: "ant_node::storage::disk_precheck",
            key = %hex::encode(offer.key),
            "Rejecting fresh replication offer before payment verification: {e}"
        );
        send_replication_response(
            source,
            p2p_node,
            request_id,
            ReplicationMessageBody::FreshReplicationResponse(FreshReplicationResponse::Rejected {
                key: offer.key,
                reason: e.to_string(),
            }),
            rr_message_id,
        )
        .await;
        return Ok(());
    }

    // Gap 1: Validate PoP via PaymentVerifier. Fresh replication is still
    // part of the immediate write fan-out: this receiver is about to store the
    // record as if the client had PUT it here directly. Storage admission
    // was checked above before proof work. FreshReplication verification is
    // identical to ClientPut — store-strength cache semantics, paid-quote
    // issuer K-closeness checks for single-node proofs, merkle candidate
    // closeness for merkle proofs, and the same price-floor policy — the
    // distinct context only labels price-floor telemetry.
    match payment_verifier
        .verify_payment(
            &offer.key,
            Some(&offer.proof_of_payment),
            fresh_offer_payment_context(),
        )
        .await
    {
        Ok(status) if status.can_store() => {
            debug!(
                "PoP validated for fresh offer key {}",
                hex::encode(offer.key)
            );
        }
        Ok(_) => {
            send_replication_response(
                source,
                p2p_node,
                request_id,
                ReplicationMessageBody::FreshReplicationResponse(
                    FreshReplicationResponse::Rejected {
                        key: offer.key,
                        reason: "Payment verification failed: payment required".to_string(),
                    },
                ),
                rr_message_id,
            )
            .await;
            return Ok(());
        }
        Err(e) => {
            warn!(
                "PoP verification error for key {}: {e}",
                hex::encode(offer.key)
            );
            send_replication_response(
                source,
                p2p_node,
                request_id,
                ReplicationMessageBody::FreshReplicationResponse(
                    FreshReplicationResponse::Rejected {
                        key: offer.key,
                        reason: format!("Payment verification error: {e}"),
                    },
                ),
                rr_message_id,
            )
            .await;
            return Ok(());
        }
    }

    // Rule 6: add to PaidForList.
    if let Err(e) = paid_list.insert(&offer.key).await {
        warn!("Failed to add key to PaidForList: {e}");
    }

    // Store the record.
    match storage.put(&offer.key, &offer.data).await {
        Ok(_) => {
            send_replication_response(
                source,
                p2p_node,
                request_id,
                ReplicationMessageBody::FreshReplicationResponse(
                    FreshReplicationResponse::Accepted { key: offer.key },
                ),
                rr_message_id,
            )
            .await;
        }
        Err(e) => {
            send_replication_response(
                source,
                p2p_node,
                request_id,
                ReplicationMessageBody::FreshReplicationResponse(
                    FreshReplicationResponse::Rejected {
                        key: offer.key,
                        reason: e.to_string(),
                    },
                ),
                rr_message_id,
            )
            .await;
        }
    }

    Ok(())
}

async fn handle_paid_notify(
    _source: &PeerId,
    notify: &protocol::PaidNotify,
    paid_list: &Arc<PaidList>,
    payment_verifier: &Arc<PaymentVerifier>,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
) -> Result<()> {
    let self_id = *p2p_node.peer_id();

    // Rule 3: validate PoP presence before adding.
    if notify.proof_of_payment.is_empty() {
        return Ok(());
    }

    // Check if we're in PaidCloseGroup for this key.
    if !admission::is_in_paid_close_group(
        &self_id,
        &notify.key,
        p2p_node,
        config.paid_list_close_group_size,
    )
    .await
    {
        return Ok(());
    }

    // Gap 1: Validate PoP via PaymentVerifier. PaidNotify admits fresh
    // paid-list metadata, so local paid-list close-group membership was checked
    // above before proof work. The verifier then runs the same payment proof
    // checks as ClientPut while writing a paid-list-strength cache entry.
    match payment_verifier
        .verify_payment(
            &notify.key,
            Some(&notify.proof_of_payment),
            paid_notify_payment_context(),
        )
        .await
    {
        Ok(status) if status.can_store() => {
            debug!(
                "PoP validated for paid notify key {}",
                hex::encode(notify.key)
            );
        }
        Ok(_) => {
            warn!(
                "Paid notify rejected: payment required for key {}",
                hex::encode(notify.key)
            );
            return Ok(());
        }
        Err(e) => {
            warn!(
                "PoP verification error for paid notify key {}: {e}",
                hex::encode(notify.key)
            );
            return Ok(());
        }
    }

    if let Err(e) = paid_list.insert(&notify.key).await {
        warn!("Failed to add paid notify key to PaidForList: {e}");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_neighbor_sync_request(
    source: &PeerId,
    request: &protocol::NeighborSyncRequest,
    p2p_node: &Arc<P2PNode>,
    storage: &Arc<LmdbStorage>,
    paid_list: &Arc<PaidList>,
    queues: &Arc<RwLock<ReplicationQueues>>,
    config: &ReplicationConfig,
    is_bootstrapping: bool,
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    sync_history: &Arc<RwLock<HashMap<PeerId, PeerSyncRecord>>>,
    sync_cycle_epoch: &Arc<RwLock<u64>>,
    repair_proofs: &Arc<RwLock<RepairProofs>>,
    my_commitment: Option<StorageCommitment>,
    request_id: u64,
    rr_message_id: Option<&str>,
) -> Result<()> {
    let self_id = *p2p_node.peer_id();

    // No per-request hint count limit: the wire message size limit
    // (MAX_REPLICATION_MESSAGE_SIZE) already caps the payload. Unlike audit
    // challenges, sync hints don't drive expensive computation — they just
    // enter the verification queue. A per-request limit here would break
    // bootstrap replication for newly-joined nodes with 0 stored chunks.

    // Build response (outbound hints).
    let (response, sent_replica_hints, sender_in_rt) =
        neighbor_sync::handle_sync_request_with_proofs(
            source,
            request,
            p2p_node,
            storage,
            paid_list,
            config,
            is_bootstrapping,
            my_commitment.clone(),
        )
        .await;

    // Send response.
    let response_sent = send_replication_response_checked(
        source,
        p2p_node,
        request_id,
        ReplicationMessageBody::NeighborSyncResponse(response),
        rr_message_id,
    )
    .await;

    // Process inbound hints only if sender is in LocalRT (Rule 4-6).
    if !sender_in_rt {
        return Ok(());
    }

    // Update sync history for this peer before recording repair proofs so a
    // same-tick audit cannot combine a fresh key proof with stale peer maturity.
    {
        let mut history = sync_history.write().await;
        let record = history.entry(*source).or_insert(PeerSyncRecord {
            last_sync: None,
            cycles_since_sync: 0,
        });
        record.last_sync = Some(Instant::now());
        record.cycles_since_sync = 0;
    }

    if response_sent && !request.bootstrapping {
        record_sent_replica_hints(source, &sent_replica_hints, repair_proofs, sync_cycle_epoch)
            .await;
    }

    // Admit inbound hints and queue for verification.
    let outcome = admit_and_queue_hints(
        &self_id,
        source,
        &request.replica_hints,
        &request.paid_hints,
        p2p_node,
        config,
        storage,
        paid_list,
        queues,
    )
    .await;

    // Track discovered keys for bootstrap drain detection so that hints
    // admitted via inbound sync requests are not missed. Capacity-rejected
    // hints keep this source on the "not yet drained" list until its next
    // sync re-admits them; a clean cycle clears the source.
    if is_bootstrapping {
        if !outcome.discovered.is_empty() {
            bootstrap::track_discovered_keys(bootstrap_state, &outcome.discovered).await;
        }
        if outcome.capacity_rejected_count > 0 {
            bootstrap::note_capacity_rejected(bootstrap_state, *source).await;
        } else {
            bootstrap::clear_capacity_rejected(bootstrap_state, source).await;
        }
    }

    Ok(())
}

async fn handle_verification_request(
    source: &PeerId,
    request: &protocol::VerificationRequest,
    storage: &Arc<LmdbStorage>,
    paid_list: &Arc<PaidList>,
    p2p_node: &Arc<P2PNode>,
    request_id: u64,
    rr_message_id: Option<&str>,
) -> Result<()> {
    // No per-request key count limit: the wire message size limit
    // (MAX_REPLICATION_MESSAGE_SIZE) already caps the payload. Verification
    // does cheap storage lookups per key, not expensive computation like
    // audit digest generation.

    #[allow(clippy::cast_possible_truncation)]
    let keys_len = request.keys.len() as u32;
    let paid_check_set: HashSet<u32> = request
        .paid_list_check_indices
        .iter()
        .copied()
        .filter(|&idx| {
            if idx >= keys_len {
                warn!(
                    "Verification request from {source}: paid_list_check_index {idx} out of bounds (keys.len() = {})",
                    request.keys.len(),
                );
                false
            } else {
                true
            }
        })
        .collect();

    let mut results = Vec::with_capacity(request.keys.len());
    for (i, key) in request.keys.iter().enumerate() {
        let present = storage.exists(key).unwrap_or(false);
        let paid = if paid_check_set.contains(&u32::try_from(i).unwrap_or(u32::MAX)) {
            Some(paid_list.contains(key).unwrap_or(false))
        } else {
            None
        };
        results.push(protocol::KeyVerificationResult {
            key: *key,
            present,
            paid,
        });
    }

    send_replication_response(
        source,
        p2p_node,
        request_id,
        ReplicationMessageBody::VerificationResponse(VerificationResponse { results }),
        rr_message_id,
    )
    .await;

    Ok(())
}

async fn handle_fetch_request(
    source: &PeerId,
    request: &protocol::FetchRequest,
    storage: &Arc<LmdbStorage>,
    p2p_node: &Arc<P2PNode>,
    request_id: u64,
    rr_message_id: Option<&str>,
) -> Result<()> {
    let response = match storage.get(&request.key).await {
        Ok(Some(data)) => protocol::FetchResponse::Success {
            key: request.key,
            data,
        },
        Ok(None) => protocol::FetchResponse::NotFound { key: request.key },
        Err(e) => protocol::FetchResponse::Error {
            key: request.key,
            reason: format!("{e}"),
        },
    };

    send_replication_response(
        source,
        p2p_node,
        request_id,
        ReplicationMessageBody::FetchResponse(response),
        rr_message_id,
    )
    .await;

    Ok(())
}

/// Responder for an incoming `AuditChallenge` (responsible-chunk audit #2, and
/// the prune-confirmation audit, which reuses the same wire message): reply with
/// per-key possession digests.
async fn handle_audit_challenge_msg(
    source: &PeerId,
    challenge: &protocol::AuditChallenge,
    storage: &Arc<LmdbStorage>,
    p2p_node: &Arc<P2PNode>,
    is_bootstrapping: bool,
    request_id: u64,
    rr_message_id: Option<&str>,
) -> Result<()> {
    #[allow(clippy::cast_possible_truncation)]
    let stored_chunks = storage.current_chunks().map_or(0, |c| c as usize);
    info!(
        "Audit challenge received: kind=responsible keys={} bootstrapping={} request_response={}",
        challenge.keys.len(),
        is_bootstrapping,
        rr_message_id.is_some(),
    );

    let response = audit::handle_audit_challenge(
        challenge,
        storage,
        p2p_node.peer_id(),
        is_bootstrapping,
        stored_chunks,
    )
    .await;
    let response_kind = audit_response_kind(&response);

    let sent = send_replication_response_checked(
        source,
        p2p_node,
        request_id,
        ReplicationMessageBody::AuditResponse(response),
        rr_message_id,
    )
    .await;
    if sent {
        info!(
            "Audit challenge reply sent: kind=responsible response={} keys={} request_response={}",
            response_kind,
            challenge.keys.len(),
            rr_message_id.is_some(),
        );
    } else {
        warn!(
            "Audit challenge reply not sent: kind=responsible response={} keys={} request_response={}",
            response_kind,
            challenge.keys.len(),
            rr_message_id.is_some(),
        );
    }

    Ok(())
}

fn audit_response_kind(response: &protocol::AuditResponse) -> &'static str {
    match response {
        protocol::AuditResponse::Digests { .. } => "digests",
        protocol::AuditResponse::Bootstrapping { .. } => "bootstrapping",
        protocol::AuditResponse::Rejected { .. } => "rejected",
    }
}

fn subtree_audit_response_kind(response: &protocol::SubtreeAuditResponse) -> &'static str {
    match response {
        protocol::SubtreeAuditResponse::Proof { .. } => "proof",
        protocol::SubtreeAuditResponse::Bootstrapping { .. } => "bootstrapping",
        protocol::SubtreeAuditResponse::Rejected { .. } => "rejected",
    }
}

fn subtree_slice_response_kind(response: &protocol::SubtreeSliceResponse) -> &'static str {
    match response {
        protocol::SubtreeSliceResponse::Items { .. } => "items",
        protocol::SubtreeSliceResponse::Bootstrapping { .. } => "bootstrapping",
        protocol::SubtreeSliceResponse::Rejected { .. } => "rejected",
    }
}

// ---------------------------------------------------------------------------
// Message sending helper
// ---------------------------------------------------------------------------

/// Send a replication response message as a best-effort reply.
///
/// Encode and send failures are logged by the checked helper. Most response
/// paths do not need to branch on send success, so this wrapper keeps those
/// call sites explicit about their best-effort behavior.
async fn send_replication_response(
    peer: &PeerId,
    p2p_node: &Arc<P2PNode>,
    request_id: u64,
    body: ReplicationMessageBody,
    rr_message_id: Option<&str>,
) {
    let _ =
        send_replication_response_checked(peer, p2p_node, request_id, body, rr_message_id).await;
}

/// Send a replication response message and report whether it was accepted.
///
/// Returns `true` after the message is encoded and accepted by the P2P send
/// path. Returns `false` after logging an encode or send failure. Repair-proof
/// recording uses this to avoid trusting hints that were not actually sent.
///
/// When `rr_message_id` is `Some`, the response is sent via the `/rr/`
/// request-response path so saorsa-core can route it back to the caller's
/// `send_request` future. Otherwise it is sent as a plain message.
async fn send_replication_response_checked(
    peer: &PeerId,
    p2p_node: &Arc<P2PNode>,
    request_id: u64,
    body: ReplicationMessageBody,
    rr_message_id: Option<&str>,
) -> bool {
    let msg = ReplicationMessage { request_id, body };
    let encoded = match msg.encode() {
        Ok(data) => data,
        Err(e) => {
            warn!("Failed to encode replication response: {e}");
            return false;
        }
    };
    // V2-684: per-peer served-bytes attribution for the heavy serve paths.
    // `FetchResponse` carries ~99% of served bytes; `NeighborSyncResponse` is
    // included for completeness. Other response variants (verification/audit/
    // commitment) are intentionally excluded — the round-2 audit reply is now a
    // few-KB verified slice (V2-685), not a full-chunk transfer, so it is light.
    if matches!(
        msg.body,
        ReplicationMessageBody::FetchResponse(_) | ReplicationMessageBody::NeighborSyncResponse(_)
    ) {
        protocol::record_served(peer, encoded.len());
    }
    let protocol = response_protocol_for(&msg.body);
    let result = if let Some(msg_id) = rr_message_id {
        p2p_node
            .send_response(peer, protocol, msg_id, encoded)
            .await
    } else {
        p2p_node.send_message(peer, protocol, encoded, &[]).await
    };
    if let Err(e) = result {
        debug!("Failed to send replication response to {peer}: {e}");
        return false;
    }
    true
}

async fn record_sent_replica_hints(
    peer: &PeerId,
    hints: &[neighbor_sync::SentReplicaHint],
    repair_proofs: &Arc<RwLock<RepairProofs>>,
    sync_cycle_epoch: &Arc<RwLock<u64>>,
) {
    if hints.is_empty() {
        return;
    }

    let hinted_at_epoch = *sync_cycle_epoch.read().await;
    let mut proofs = repair_proofs.write().await;
    for hint in hints {
        if proofs.record_replica_hint_sent(*peer, hint.key, &hint.close_peers, hinted_at_epoch) {
            debug!(
                "Recorded repair hint proof for peer {peer} and key {}",
                hex::encode(hint.key)
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Neighbor sync round
// ---------------------------------------------------------------------------

/// Run one neighbor sync round.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_neighbor_sync_round(
    p2p_node: &Arc<P2PNode>,
    storage: &Arc<LmdbStorage>,
    paid_list: &Arc<PaidList>,
    queues: &Arc<RwLock<ReplicationQueues>>,
    config: &ReplicationConfig,
    sync_state: &Arc<RwLock<NeighborSyncState>>,
    sync_history: &Arc<RwLock<HashMap<PeerId, PeerSyncRecord>>>,
    sync_cycle_epoch: &Arc<RwLock<u64>>,
    repair_proofs: &Arc<RwLock<RepairProofs>>,
    is_bootstrapping: &Arc<RwLock<bool>>,
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    commitment_state: &Arc<ResponderCommitmentState>,
    last_commitment_by_peer: &Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>>,
    ever_capable_peers: &Arc<RwLock<HashSet<PeerId>>>,
    sig_verify_attempts: &Arc<RwLock<HashMap<PeerId, Instant>>>,
    gossip_audit: &GossipAuditTrigger,
) {
    let self_id = *p2p_node.peer_id();
    let bootstrapping = *is_bootstrapping.read().await;

    // Check if cycle is complete; start new one if needed.
    // We check under a read lock, then release it before the expensive
    // prune pass and DHT snapshot so other tasks are not starved.
    let cycle_complete = sync_state.read().await.is_cycle_complete();
    if cycle_complete {
        // A completed local neighbor-sync cycle advances the epoch component
        // of repair-proof maturity. The per-key wall-clock minimum age is
        // checked when audits are selected.
        {
            let mut history = sync_history.write().await;
            for record in history.values_mut() {
                record.cycles_since_sync = record.cycles_since_sync.saturating_add(1);
            }
        }
        {
            let mut epoch = sync_cycle_epoch.write().await;
            *epoch = epoch.saturating_add(1);
        }

        // Post-cycle pruning (Section 11) — runs without holding sync_state.
        // Prune candidacy is unconditional once the hysteresis elapses;
        // bootstrap state only defers the remote prune-confirmation audits
        // until bootstrap has drained.
        let allow_remote_prune_audits = !bootstrapping && bootstrap_state.read().await.is_drained();
        pruning::run_prune_pass_with_context(pruning::PrunePassContext {
            self_id: &self_id,
            storage,
            paid_list,
            p2p_node,
            config,
            sync_state,
            repair_proofs,
            allow_remote_prune_audits,
            commitment_state: Some(commitment_state),
        })
        .await;

        // Take fresh close-neighbor snapshot (DHT query, no lock held).
        let neighbors =
            neighbor_sync::snapshot_close_neighbors(p2p_node, &self_id, config.neighbor_sync_scope)
                .await;

        // Now re-acquire write lock and re-check before swapping cycle.
        let mut state = sync_state.write().await;
        if state.is_cycle_complete() {
            // Preserve cooldown and bootstrap-claim tracking across cycles.
            // Claims have a 24h lifecycle vs 10-20 min cycles — dropping them
            // would reset the abuse detection timer every cycle.
            let old_sync_times = std::mem::take(&mut state.last_sync_times);
            let old_bootstrap_claims = std::mem::take(&mut state.bootstrap_claims);
            let old_bootstrap_claim_history = std::mem::take(&mut state.bootstrap_claim_history);
            let old_prune_cursor = state.prune_cursor;
            *state = NeighborSyncState::new_cycle(neighbors);
            state.last_sync_times = old_sync_times;
            state.bootstrap_claims = old_bootstrap_claims;
            state.bootstrap_claim_history = old_bootstrap_claim_history;
            state.prune_cursor = old_prune_cursor;
        }
    }

    // Select batch of peers.
    let batch = {
        let mut state = sync_state.write().await;
        neighbor_sync::select_sync_batch(
            &mut state,
            config.neighbor_sync_peer_count,
            config.neighbor_sync_cooldown,
        )
    };

    if batch.is_empty() {
        return;
    }

    debug!("Neighbor sync: syncing with {} peers", batch.len());

    // Snapshot our current commitment once per round so all peers in
    // this batch see the same thing (gossip is the responder's attestation;
    // same value across the batch is fine and reduces RwLock churn). Atomically
    // snapshot + mark-gossiped so we stay answerable for exactly what we emit
    // (ADR-0002 retention), with no TOCTOU vs a concurrent retire/rotate.
    let my_commitment = commitment_state
        .current_for_gossip()
        .map(|b| b.commitment().clone());

    let mut hints_by_peer = neighbor_sync::build_sync_hints_for_peers(
        &batch,
        storage,
        paid_list,
        p2p_node,
        config.close_group_size,
        config.paid_list_close_group_size,
    )
    .await;

    // Sync with each peer in the batch.
    for peer in &batch {
        let hints = hints_by_peer.remove(peer).unwrap_or_default();
        let outcome = neighbor_sync::sync_with_peer_with_hints(
            peer,
            p2p_node,
            config,
            bootstrapping,
            hints,
            my_commitment.clone(),
        )
        .await;

        if let Some(outcome) = outcome {
            handle_sync_response(
                &self_id,
                peer,
                &outcome.response,
                &outcome.sent_replica_hints,
                p2p_node,
                config,
                bootstrapping,
                bootstrap_state,
                storage,
                paid_list,
                queues,
                sync_state,
                sync_history,
                sync_cycle_epoch,
                repair_proofs,
                last_commitment_by_peer,
                ever_capable_peers,
                sig_verify_attempts,
                gossip_audit,
            )
            .await;
        } else {
            // Sync failed -- remove peer and try to fill slot.
            let replacement = {
                let mut state = sync_state.write().await;
                neighbor_sync::handle_sync_failure(&mut state, peer, config.neighbor_sync_cooldown)
            };

            // Attempt sync with the replacement peer (if one was found).
            if let Some(replacement_peer) = replacement {
                let mut replacement_hints = neighbor_sync::build_sync_hints_for_peers(
                    std::slice::from_ref(&replacement_peer),
                    storage,
                    paid_list,
                    p2p_node,
                    config.close_group_size,
                    config.paid_list_close_group_size,
                )
                .await;
                let hints = replacement_hints
                    .remove(&replacement_peer)
                    .unwrap_or_default();
                let replacement_outcome = neighbor_sync::sync_with_peer_with_hints(
                    &replacement_peer,
                    p2p_node,
                    config,
                    bootstrapping,
                    hints,
                    my_commitment.clone(),
                )
                .await;

                if let Some(outcome) = replacement_outcome {
                    handle_sync_response(
                        &self_id,
                        &replacement_peer,
                        &outcome.response,
                        &outcome.sent_replica_hints,
                        p2p_node,
                        config,
                        bootstrapping,
                        bootstrap_state,
                        storage,
                        paid_list,
                        queues,
                        sync_state,
                        sync_history,
                        sync_cycle_epoch,
                        repair_proofs,
                        last_commitment_by_peer,
                        ever_capable_peers,
                        sig_verify_attempts,
                        gossip_audit,
                    )
                    .await;
                }
            }
        }
    }
}

/// Process a successful neighbor sync response: record the sync, check for
/// bootstrap claim abuse, and admit inbound hints.
#[allow(clippy::too_many_arguments)]
async fn handle_sync_response(
    self_id: &PeerId,
    peer: &PeerId,
    resp: &NeighborSyncResponse,
    sent_replica_hints: &[neighbor_sync::SentReplicaHint],
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    bootstrapping: bool,
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    storage: &Arc<LmdbStorage>,
    paid_list: &Arc<PaidList>,
    queues: &Arc<RwLock<ReplicationQueues>>,
    sync_state: &Arc<RwLock<NeighborSyncState>>,
    sync_history: &Arc<RwLock<HashMap<PeerId, PeerSyncRecord>>>,
    sync_cycle_epoch: &Arc<RwLock<u64>>,
    repair_proofs: &Arc<RwLock<RepairProofs>>,
    last_commitment_by_peer: &Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>>,
    ever_capable_peers: &Arc<RwLock<HashSet<PeerId>>>,
    sig_verify_attempts: &Arc<RwLock<HashMap<PeerId, Instant>>>,
    gossip_audit: &GossipAuditTrigger,
) {
    // Ingest the peer's commitment if they piggybacked one on the response.
    // Same verification as the request path (peer-id binding + signature);
    // forged commitments are dropped at the edge. A *changed* commitment here
    // is a gossip-audit trigger just like on the request path — so a peer that
    // only ever answers sync (never initiates) is still audited (ADR-0002).
    if let Some(target) = ingest_peer_commitment(
        peer,
        resp.commitment.as_ref(),
        p2p_node,
        last_commitment_by_peer,
        ever_capable_peers,
        sig_verify_attempts,
    )
    .await
    {
        maybe_trigger_gossip_audit(gossip_audit, peer, target).await;
    }

    // Record successful sync.
    {
        let mut state = sync_state.write().await;
        neighbor_sync::record_successful_sync(&mut state, peer);
    }
    {
        let mut history = sync_history.write().await;
        let record = history.entry(*peer).or_insert(PeerSyncRecord {
            last_sync: None,
            cycles_since_sync: 0,
        });
        record.last_sync = Some(Instant::now());
        record.cycles_since_sync = 0;
    }

    // Process inbound hints from response (skip if peer is bootstrapping).
    if resp.bootstrapping {
        // Gap 6: BootstrapClaimAbuse grace period enforcement.
        // Separate state mutation from network I/O to avoid holding the
        // write lock across report_trust_event.
        let should_report = {
            let now = Instant::now();
            let mut state = sync_state.write().await;
            match state.observe_bootstrap_claim(*peer, now, config.bootstrap_claim_grace_period) {
                BootstrapClaimObservation::WithinGrace { .. } => false,
                BootstrapClaimObservation::PastGrace { first_seen } => {
                    warn!(
                        "Peer {peer} has been claiming bootstrap for {:?}, \
                         exceeding grace period of {:?} — reporting abuse",
                        now.duration_since(first_seen),
                        config.bootstrap_claim_grace_period,
                    );
                    true
                }
                BootstrapClaimObservation::Repeated { first_seen } => {
                    warn!(
                        "Peer {peer} repeated bootstrap claim after previously stopping; \
                         first claim was {:?} ago — reporting abuse",
                        now.duration_since(first_seen),
                    );
                    true
                }
            }
        };
        if should_report {
            p2p_node
                .report_trust_event(
                    peer,
                    TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                )
                .await;
        }
    } else {
        // Peer is not claiming bootstrap; clear active claim while retaining
        // history so the peer cannot start a second grace window later.
        {
            let mut state = sync_state.write().await;
            state.clear_active_bootstrap_claim(peer);
        }
        record_sent_replica_hints(peer, sent_replica_hints, repair_proofs, sync_cycle_epoch).await;
        let outcome = admit_and_queue_hints(
            self_id,
            peer,
            &resp.replica_hints,
            &resp.paid_hints,
            p2p_node,
            config,
            storage,
            paid_list,
            queues,
        )
        .await;

        // Track discovered keys for bootstrap drain detection so that hints
        // admitted via regular neighbor sync are not missed. Capacity-
        // rejected hints keep this source on the "not yet drained" list
        // until its next sync replays them; a clean cycle clears it.
        if bootstrapping {
            if !outcome.discovered.is_empty() {
                bootstrap::track_discovered_keys(bootstrap_state, &outcome.discovered).await;
            }
            if outcome.capacity_rejected_count > 0 {
                bootstrap::note_capacity_rejected(bootstrap_state, *peer).await;
            } else {
                bootstrap::clear_capacity_rejected(bootstrap_state, peer).await;
            }
        }
    }
}

/// Admit hints and queue them for verification, returning newly-discovered keys.
///
/// Shared by neighbor-sync request handling, response handling, and bootstrap
/// sync so that admission + queueing logic lives in one place.
#[allow(clippy::too_many_arguments)]
/// Outcome of [`admit_and_queue_hints`].
///
/// `capacity_rejected_count` is non-zero when one or more legitimately
/// admissible hints were dropped because `pending_verify`'s global or
/// per-source bound was hit. Callers that care about completeness
/// (bootstrap drain accounting) MUST NOT treat their work as complete while
/// this is > 0 — the source will need to re-hint after capacity frees up.
struct AdmissionOutcome {
    discovered: HashSet<XorName>,
    capacity_rejected_count: usize,
}

#[allow(clippy::too_many_arguments)]
async fn admit_and_queue_hints(
    self_id: &PeerId,
    source_peer: &PeerId,
    replica_hints: &[XorName],
    paid_hints: &[XorName],
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    storage: &Arc<LmdbStorage>,
    paid_list: &Arc<PaidList>,
    queues: &Arc<RwLock<ReplicationQueues>>,
) -> AdmissionOutcome {
    let pending_keys: HashSet<XorName> = {
        let q = queues.read().await;
        q.pending_keys().into_iter().collect()
    };

    let admitted = admission::admit_hints(
        self_id,
        replica_hints,
        paid_hints,
        p2p_node,
        config,
        storage,
        paid_list,
        &pending_keys,
    )
    .await;

    let mut discovered = HashSet::new();
    let mut capacity_rejected_count: usize = 0;
    let mut q = queues.write().await;
    let now = Instant::now();

    for key in admitted.replica_keys {
        if !storage.exists(&key).unwrap_or(false) {
            let result = q.add_pending_verify(
                key,
                VerificationEntry {
                    state: VerificationState::PendingVerify,
                    pipeline: HintPipeline::Replica,
                    verified_sources: Vec::new(),
                    tried_sources: HashSet::new(),
                    created_at: now,
                    hint_sender: *source_peer,
                },
            );
            match result {
                crate::replication::scheduling::AdmissionResult::Admitted => {
                    discovered.insert(key);
                }
                crate::replication::scheduling::AdmissionResult::AlreadyPresent => {}
                crate::replication::scheduling::AdmissionResult::CapacityRejected => {
                    capacity_rejected_count += 1;
                }
            }
        }
    }

    for key in admitted.paid_only_keys {
        let result = q.add_pending_verify(
            key,
            VerificationEntry {
                state: VerificationState::PendingVerify,
                pipeline: HintPipeline::PaidOnly,
                verified_sources: Vec::new(),
                tried_sources: HashSet::new(),
                created_at: now,
                hint_sender: *source_peer,
            },
        );
        match result {
            crate::replication::scheduling::AdmissionResult::Admitted => {
                discovered.insert(key);
            }
            crate::replication::scheduling::AdmissionResult::AlreadyPresent => {}
            crate::replication::scheduling::AdmissionResult::CapacityRejected => {
                capacity_rejected_count += 1;
            }
        }
    }

    if capacity_rejected_count > 0 {
        debug!(
            "admit_and_queue_hints from {source_peer}: {capacity_rejected_count} hints \
             rejected at queue capacity; source will need to re-hint after pending_verify drains"
        );
    }

    AdmissionOutcome {
        discovered,
        capacity_rejected_count,
    }
}

// ---------------------------------------------------------------------------
// Verification cycle
// ---------------------------------------------------------------------------

/// Run one verification cycle: process pending keys through quorum checks.
#[allow(clippy::too_many_lines)]
async fn run_verification_cycle(ctx: VerificationCycleContext<'_>) {
    let cycle_started = Instant::now();
    let VerificationCycleContext {
        p2p_node,
        paid_list,
        storage,
        queues,
        config,
        bootstrap_state,
        is_bootstrapping,
        bootstrap_complete_notify,
        last_commitment_by_peer,
        ever_capable_peers,
        recent_provers,
    } = ctx;

    // Evict stale entries that have been pending too long (e.g. unreachable
    // verification targets during a network partition).
    {
        let mut q = queues.write().await;
        q.evict_stale(config::PENDING_VERIFY_MAX_AGE);
    }

    let pending_keys = {
        let q = queues.read().await;
        q.pending_keys()
    };

    if pending_keys.is_empty() {
        return;
    }
    let initial_pending_count = pending_keys.len();

    let self_id = *p2p_node.peer_id();

    // Step 1: Check local PaidForList for fast-path authorization (Section 9,
    // step 4).
    let mut local_paid_presence_probe_keys = Vec::new();
    let mut local_paid_paid_only_keys = Vec::new();
    let mut keys_needing_network = Vec::new();
    let mut terminal_keys: Vec<XorName> = Vec::new();
    {
        let mut q = queues.write().await;
        for key in &pending_keys {
            if paid_list.contains(key).unwrap_or(false) {
                if let Some(pipeline) =
                    q.set_pending_state(key, VerificationState::PaidListVerified)
                {
                    match pipeline {
                        HintPipeline::PaidOnly => {
                            // Paid-only + local paid state needs one more
                            // storage-admission check outside this lock: if we
                            // are also in the close group plus storage margin,
                            // the hint can repair a missing replica.
                            local_paid_paid_only_keys.push(*key);
                        }
                        HintPipeline::Replica => {
                            // Local paid-list membership authorizes the key.
                            // We still need a presence probe to discover fetch
                            // sources, but we must not require remote paid
                            // majority or presence quorum.
                            local_paid_presence_probe_keys.push(*key);
                        }
                    }
                }
            } else {
                keys_needing_network.push(*key);
            }
        }
    }

    if !local_paid_paid_only_keys.is_empty() {
        let mut terminal_paid_only = Vec::new();
        for key in local_paid_paid_only_keys {
            if storage.exists(&key).unwrap_or(false) {
                terminal_paid_only.push(key);
            } else if admission::is_responsible(
                &self_id,
                &key,
                p2p_node,
                storage_admission_width(config.close_group_size),
            )
            .await
            {
                local_paid_presence_probe_keys.push(key);
            } else {
                terminal_paid_only.push(key);
            }
        }

        if !terminal_paid_only.is_empty() {
            let mut q = queues.write().await;
            for key in terminal_paid_only {
                q.remove_pending(&key);
                terminal_keys.push(key);
            }
        }
    }

    let local_paid_probe_count = local_paid_presence_probe_keys.len();
    let keys_needing_network_count = keys_needing_network.len();

    // Step 1b: Local paid-list hit for fetch-eligible keys. Per Section 9
    // step 4, authorization succeeds immediately; run a presence-only probe
    // to find any holder we can fetch from.
    if !local_paid_presence_probe_keys.is_empty() {
        let targets = quorum::compute_presence_targets(
            &local_paid_presence_probe_keys,
            p2p_node,
            config,
            &self_id,
        )
        .await;
        let evidence = quorum::run_verification_round(
            &local_paid_presence_probe_keys,
            &targets,
            p2p_node,
            config,
        )
        .await;

        let mut q = queues.write().await;
        for key in local_paid_presence_probe_keys {
            if storage.exists(&key).unwrap_or(false) {
                q.remove_pending(&key);
                terminal_keys.push(key);
                continue;
            }
            let sources = evidence.get(&key).map_or_else(Vec::new, |ev| {
                quorum::present_sources_for_key(&key, ev, &targets)
            });
            if sources.is_empty() {
                // Terminal failure: remove pending and report. No fetch path.
                q.remove_pending(&key);
                warn!(
                    "Locally paid key {} has no responding holders (possible data loss)",
                    hex::encode(key)
                );
                terminal_keys.push(key);
            } else {
                let distance = crate::client::xor_distance(&key, p2p_node.peer_id().as_bytes());
                // Atomic remove+enqueue: if fetch_queue is at capacity, the
                // pending entry is preserved and retried next cycle (no
                // silent drop of verified replica-repair work).
                let _ = q.promote_pending_to_fetch(key, distance, sources);
            }
        }
    }

    // Steps 2-5: Network verification (skipped if all keys resolved locally).
    if !keys_needing_network.is_empty() {
        // Step 2: Compute targets and run network verification round.
        let targets =
            quorum::compute_verification_targets(&keys_needing_network, p2p_node, config, &self_id)
                .await;

        let evidence =
            quorum::run_verification_round(&keys_needing_network, &targets, p2p_node, config).await;

        // Step 3: Evaluate results — collect outcomes without holding the write
        // lock across paid-list I/O.
        //
        // v12 §6 holder-eligibility: snapshot the per-peer last-commitment
        // table and recent_provers cache up front so the synchronous
        // evaluate_key_evidence_with_holder_check predicate can consult
        // them without awaiting. The predicate downgrades a Present
        // claim to Unresolved unless the peer is credited for that key.
        // Snapshot per-peer commitment data. We need two views:
        //   - `commitment_by_peer_snapshot`: peers that currently have
        //     a verified commitment record on file (used to look up
        //     their current hash).
        //   - `capable_peer_snapshot`: the sticky "ever v12-capable"
        //     set. Sourced from a separate set rather than the
        //     commitment map so eviction (PeerRemoved cleanup, sybil
        //     cap at `MAX_LAST_COMMITMENT_BY_PEER`) does NOT downgrade
        //     a previously-v12 peer to "legacy" credit-unconditionally.
        //     Legacy / pre-v12 peers that have never sent a commitment
        //     remain absent from the set and are credited via the
        //     legacy path so mixed-version networks stay live.
        let commitment_by_peer_snapshot: HashMap<PeerId, [u8; 32]> = {
            let map = last_commitment_by_peer.read().await;
            map.iter()
                // Read the CACHED hash (§13) — no per-cycle re-serialize/re-hash
                // of every peer's ~5 KiB commitment.
                .filter_map(|(p, rec)| rec.commitment_hash().map(|h| (*p, h)))
                .collect()
        };
        let capable_peer_snapshot: HashSet<PeerId> = ever_capable_peers.read().await.clone();
        // Take a full snapshot of recent_provers under the read lock,
        // then release. The cache is bounded (16/key × keys), so the
        // clone is cheap.
        let provers_snapshot = recent_provers.read().await.clone();
        // For the replica-fetch path, we need to know whether THIS
        // node already holds the key being verified. The v12 §6
        // holder-credit gate is meant to prevent uncredited Present
        // claims from contributing to paid-list / reward quorum for
        // keys we DO hold (and could audit ourselves). For keys we
        // are trying to FETCH (i.e. not in local storage), there is
        // no possible local audit credit, and gating the presence
        // quorum on credit would deadlock replica-repair in a
        // fully v12-capable close group.
        let mut locally_held: HashSet<XorName> = HashSet::new();
        for key in &keys_needing_network {
            if storage.exists(key).unwrap_or(false) {
                locally_held.insert(*key);
            }
        }
        let holder_credit = |peer: &PeerId, key: &XorName| -> bool {
            if !locally_held.contains(key) {
                // Replica-fetch path: we don't hold this key, so we
                // cannot have collected audit credit for it. Trust
                // Present claims to drive fetch-source promotion;
                // chunk-PUT payment_verifier is the security backstop
                // when the bytes actually arrive.
                return true;
            }
            if !capable_peer_snapshot.contains(peer) {
                // Pre-v12 / legacy peer that has never gossiped a
                // commitment. The v12 §6 holder-eligibility check
                // doesn't apply: their Present evidence comes through
                // the legacy path and we credit it unconditionally
                // so a mixed-version network stays live during
                // transition.
                return true;
            }
            let Some(hash) = commitment_by_peer_snapshot.get(peer) else {
                // Peer is commitment_capable (sticky) but currently
                // has no live commitment record on file (e.g. their
                // last gossip was evicted from the LRU cache, or it
                // failed verification). Withhold credit until they
                // re-prove storage under a fresh commitment.
                return false;
            };
            provers_snapshot.is_credited_holder(key, peer, hash)
        };

        let mut evaluated: Vec<(XorName, KeyVerificationOutcome, HintPipeline)> = Vec::new();
        {
            let q = queues.read().await;
            for key in &keys_needing_network {
                let Some(ev) = evidence.get(key) else {
                    continue;
                };
                let Some(entry) = q.get_pending(key) else {
                    continue;
                };
                let outcome = quorum::evaluate_key_evidence_with_holder_check(
                    key,
                    ev,
                    &targets,
                    config,
                    holder_credit,
                );
                evaluated.push((*key, outcome, entry.pipeline));
            }
        } // read lock released

        // Step 4: Insert verified keys into PaidForList (no lock held).
        let mut paid_insert_keys: Vec<XorName> = Vec::new();
        for (key, outcome, _) in &evaluated {
            if matches!(
                outcome,
                KeyVerificationOutcome::QuorumVerified { .. }
                    | KeyVerificationOutcome::PaidListVerified { .. }
            ) {
                paid_insert_keys.push(*key);
            }
        }
        for key in &paid_insert_keys {
            if let Err(e) = paid_list.insert(key).await {
                warn!("Failed to add verified key to PaidForList: {e}");
            }
        }

        // Paid-only hints normally update PaidForList only. If this node is
        // also within the storage-admission group for the key, a verified
        // paid-only hint can safely repair a missing replica using sources
        // from the same verification round.
        let mut paid_only_fetch_keys: HashSet<XorName> = HashSet::new();
        for (key, outcome, pipeline) in &evaluated {
            if *pipeline == HintPipeline::PaidOnly
                && matches!(
                    outcome,
                    KeyVerificationOutcome::QuorumVerified { .. }
                        | KeyVerificationOutcome::PaidListVerified { .. }
                )
                && !storage.exists(key).unwrap_or(false)
                && admission::is_responsible(
                    &self_id,
                    key,
                    p2p_node,
                    storage_admission_width(config.close_group_size),
                )
                .await
            {
                paid_only_fetch_keys.insert(*key);
            }
        }

        // Step 5: Update queues with the evaluated outcomes.
        let mut q = queues.write().await;
        for (key, outcome, pipeline) in evaluated {
            match outcome {
                KeyVerificationOutcome::QuorumVerified { sources }
                | KeyVerificationOutcome::PaidListVerified { sources } => {
                    let fetch_eligible =
                        pipeline == HintPipeline::Replica || paid_only_fetch_keys.contains(&key);
                    if fetch_eligible && !sources.is_empty() {
                        let distance =
                            crate::client::xor_distance(&key, p2p_node.peer_id().as_bytes());
                        // Atomic remove+enqueue: on fetch_queue capacity miss
                        // the pending entry is preserved so this verified key
                        // is retried on the next cycle (no silent drop).
                        let _ = q.promote_pending_to_fetch(key, distance, sources);
                        // Not terminal — either moved to fetch queue, or
                        // retained as pending until queue drains.
                    } else if fetch_eligible && sources.is_empty() {
                        warn!(
                            "Verified storage-admitted key {} has no holders (possible data loss)",
                            hex::encode(key)
                        );
                        q.remove_pending(&key);
                        terminal_keys.push(key);
                    } else {
                        q.remove_pending(&key);
                        terminal_keys.push(key);
                    }
                }
                KeyVerificationOutcome::QuorumFailed
                | KeyVerificationOutcome::QuorumInconclusive => {
                    q.remove_pending(&key);
                    terminal_keys.push(key);
                }
            }
        }
    }

    // Step 6: Remove terminal keys from bootstrap pending set and re-check
    // the drain condition.
    update_bootstrap_after_verification(
        &terminal_keys,
        bootstrap_state,
        queues,
        is_bootstrapping,
        bootstrap_complete_notify,
    )
    .await;

    let (pending_after, fetch_after, in_flight_after) = {
        let q = queues.read().await;
        (
            q.pending_count(),
            q.fetch_queue_count(),
            q.in_flight_count(),
        )
    };
    let terminal_key_count = terminal_keys.len();
    let elapsed_ms = cycle_started.elapsed().as_millis();

    if elapsed_ms >= VERIFICATION_CYCLE_SLOW_LOG_MS {
        info!(
            target: "ant_node::replication::verification",
            "Slow replication verification cycle: pending_start={initial_pending_count}, local_paid_probe={local_paid_probe_count}, network_verify={keys_needing_network_count}, terminal={terminal_key_count}, pending_after={pending_after}, fetch_after={fetch_after}, in_flight_after={in_flight_after}, elapsed_ms={elapsed_ms}",
        );
    } else {
        debug!(
            target: "ant_node::replication::verification",
            "Replication verification cycle: pending_start={initial_pending_count}, local_paid_probe={local_paid_probe_count}, network_verify={keys_needing_network_count}, terminal={terminal_key_count}, pending_after={pending_after}, fetch_after={fetch_after}, in_flight_after={in_flight_after}, elapsed_ms={elapsed_ms}",
        );
    }
}

/// Post-verification bootstrap bookkeeping: remove terminal keys from the
/// bootstrap pending set and transition out of bootstrapping when drained.
async fn update_bootstrap_after_verification(
    terminal_keys: &[XorName],
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    queues: &Arc<RwLock<ReplicationQueues>>,
    is_bootstrapping: &Arc<RwLock<bool>>,
    bootstrap_complete_notify: &Arc<Notify>,
) {
    if terminal_keys.is_empty() || bootstrap_state.read().await.is_drained() {
        return;
    }
    {
        let mut bs = bootstrap_state.write().await;
        for key in terminal_keys {
            bs.remove_key(key);
        }
    }
    let q = queues.read().await;
    if bootstrap::check_bootstrap_drained(bootstrap_state, &q).await {
        complete_bootstrap(is_bootstrapping, bootstrap_complete_notify).await;
    }
}

/// Set `is_bootstrapping` to `false` and wake all waiters.
async fn complete_bootstrap(
    is_bootstrapping: &Arc<RwLock<bool>>,
    bootstrap_complete_notify: &Arc<Notify>,
) {
    *is_bootstrapping.write().await = false;
    bootstrap_complete_notify.notify_waiters();
    info!("Replication bootstrap complete");
}

// ---------------------------------------------------------------------------
// Fetch types and single-fetch executor
// ---------------------------------------------------------------------------

/// Result classification for a single fetch attempt.
enum FetchResult {
    /// Data fetched, integrity-checked, and stored successfully.
    Stored,
    /// Content-address integrity check failed — do not retry.
    IntegrityFailed,
    /// Source failed (network error or non-success response) — retryable.
    SourceFailed,
}

/// Outcome produced by [`execute_single_fetch`] and consumed by the fetch
/// worker loop to update queue state.
struct FetchOutcome {
    key: XorName,
    result: FetchResult,
}

#[allow(clippy::too_many_lines)]
/// Execute a single fetch request against `source` for `key`.
///
/// Handles encoding, network I/O, integrity checking, storage, and trust
/// event reporting.  Returns a [`FetchOutcome`] so the caller can update
/// queue state without holding any locks during the network round-trip.
async fn execute_single_fetch(
    p2p_node: Arc<P2PNode>,
    storage: Arc<LmdbStorage>,
    config: Arc<ReplicationConfig>,
    key: XorName,
    source: PeerId,
) -> FetchOutcome {
    let request = protocol::FetchRequest { key };
    let msg = ReplicationMessage {
        request_id: rand::thread_rng().gen::<u64>(),
        body: ReplicationMessageBody::FetchRequest(request),
    };

    let encoded = match msg.encode() {
        Ok(data) => data,
        Err(e) => {
            warn!("Failed to encode fetch request: {e}");
            return FetchOutcome {
                key,
                result: FetchResult::SourceFailed,
            };
        }
    };

    let result = p2p_node
        .send_request(
            &source,
            REPLICATION_PROTOCOL_ID,
            encoded,
            config.fetch_request_timeout,
        )
        .await;

    match result {
        Ok(response) => {
            let Ok(resp_msg) = ReplicationMessage::decode(&response.data) else {
                p2p_node
                    .report_trust_event(
                        &source,
                        TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                    )
                    .await;
                return FetchOutcome {
                    key,
                    result: FetchResult::SourceFailed,
                };
            };

            match resp_msg.body {
                ReplicationMessageBody::FetchResponse(protocol::FetchResponse::Success {
                    key: resp_key,
                    data,
                }) => {
                    // Validate the response key matches the requested key.
                    // A malicious peer could serve valid data for a different
                    // key, passing integrity checks while the requested key
                    // is falsely marked as fetched.
                    if resp_key != key {
                        warn!(
                            "Fetch response key mismatch: requested {}, got {}",
                            hex::encode(key),
                            hex::encode(resp_key)
                        );
                        p2p_node
                            .report_trust_event(
                                &source,
                                TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                            )
                            .await;
                        return FetchOutcome {
                            key,
                            result: FetchResult::IntegrityFailed,
                        };
                    }

                    // Enforce chunk size invariant on fetched data.
                    // Checked before the content-address hash to avoid
                    // hashing up to 10 MiB of oversized junk data.
                    if data.len() > crate::ant_protocol::MAX_CHUNK_SIZE {
                        warn!(
                            "Fetched record {} exceeds MAX_CHUNK_SIZE ({} > {})",
                            hex::encode(resp_key),
                            data.len(),
                            crate::ant_protocol::MAX_CHUNK_SIZE,
                        );
                        p2p_node
                            .report_trust_event(
                                &source,
                                TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                            )
                            .await;
                        return FetchOutcome {
                            key,
                            result: FetchResult::IntegrityFailed,
                        };
                    }

                    // Content-address integrity check.
                    let computed = crate::client::compute_address(&data);
                    if computed != resp_key {
                        warn!(
                            "Fetched record integrity check failed: expected {}, got {}",
                            hex::encode(resp_key),
                            hex::encode(computed)
                        );
                        p2p_node
                            .report_trust_event(
                                &source,
                                TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                            )
                            .await;
                        return FetchOutcome {
                            key,
                            result: FetchResult::IntegrityFailed,
                        };
                    }

                    if let Err(e) = storage.put(&resp_key, &data).await {
                        warn!(
                            "Failed to store fetched record {}: {e}",
                            hex::encode(resp_key)
                        );
                        return FetchOutcome {
                            key,
                            result: FetchResult::SourceFailed,
                        };
                    }

                    FetchOutcome {
                        key,
                        result: FetchResult::Stored,
                    }
                }
                ReplicationMessageBody::FetchResponse(protocol::FetchResponse::NotFound {
                    ..
                }) => {
                    // This peer was selected as a fetch source because it
                    // recently answered `Present` during verification. A
                    // subsequent NotFound is evidence of a stale/false claim
                    // or chunk wiping, so penalize lightly and try another
                    // verified source.
                    warn!(
                        "Fetch: verified source {source} returned NotFound for {}",
                        hex::encode(key)
                    );
                    p2p_node
                        .report_trust_event(
                            &source,
                            TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                        )
                        .await;
                    FetchOutcome {
                        key,
                        result: FetchResult::SourceFailed,
                    }
                }
                ReplicationMessageBody::FetchResponse(protocol::FetchResponse::Error {
                    reason,
                    ..
                }) => {
                    warn!(
                        "Fetch: peer {source} returned error for {}: {reason}",
                        hex::encode(key)
                    );
                    p2p_node
                        .report_trust_event(
                            &source,
                            TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                        )
                        .await;
                    FetchOutcome {
                        key,
                        result: FetchResult::SourceFailed,
                    }
                }
                _ => {
                    // Unexpected message type — treat as malformed.
                    p2p_node
                        .report_trust_event(
                            &source,
                            TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                        )
                        .await;
                    FetchOutcome {
                        key,
                        result: FetchResult::SourceFailed,
                    }
                }
            }
        }
        Err(e) => {
            debug!("Fetch request to {source} failed: {e}");
            // No ApplicationFailure here — P2PNode::send_request() already
            // reports ConnectionTimeout / ConnectionFailed to the TrustEngine.
            FetchOutcome {
                key,
                result: FetchResult::SourceFailed,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Audit result handler
// ---------------------------------------------------------------------------

/// Format the first confirmed-failed key as a 16-hex-char label.
///
/// Pairs with `challenged_peer` to form a stable cross-host correlation
/// handle in the audit-failure log line, e.g.
///
/// ```text
/// Audit failure for <peer>: …, `first_failed_key=0x18878f1d2d9e0612`
/// ```
///
/// Falls back to `"0x"` when the list is empty so the log line never
/// contains a misleading default.
fn first_failed_key_label(confirmed_failed_keys: &[XorName]) -> String {
    confirmed_failed_keys.first().map_or_else(
        || "0x".to_string(),
        |k| format!("0x{}", hex::encode(&k[..8])),
    )
}

/// Execute the side effects for a subtree storage-commitment audit failure.
///
/// Subtree timeouts are fully graced: the multi-round, multi-chunk challenge can
/// legitimately time out on slow or loaded honest peers, so it never touches the
/// responsible-chunk audit path or its timeout accounting. Confirmed subtree
/// failures still penalise immediately and revoke holder credit.
async fn handle_subtree_failed_audit(
    challenged_peer: &PeerId,
    confirmed_failed_key_count: usize,
    reason: &AuditFailureReason,
    p2p_node: &Arc<P2PNode>,
    sync_state: &Arc<RwLock<NeighborSyncState>>,
    recent_provers: &Arc<RwLock<RecentProvers>>,
) {
    if matches!(reason, AuditFailureReason::Timeout) {
        debug!(
            "Audit timeout for {challenged_peer} fully graced \
             (subtree audit does not evict on timeout)"
        );
        return;
    }

    // The caller already logged the rich failure line with reason + per-category
    // summary; avoid a redundant second error log here.
    let _ = confirmed_failed_key_count;
    {
        let mut state = sync_state.write().await;
        state.clear_active_bootstrap_claim(challenged_peer);
    }
    {
        let mut provers_guard = recent_provers.write().await;
        apply_audit_failure_credit_revocation(&mut provers_guard, challenged_peer, reason);
    }
    p2p_node
        .report_trust_event(
            challenged_peer,
            TrustEvent::ApplicationFailure(config::AUDIT_FAILURE_TRUST_WEIGHT),
        )
        .await;
}

/// Handle audit result: log findings and emit trust events.
async fn handle_subtree_audit_result(
    result: &AuditTickResult,
    p2p_node: &Arc<P2PNode>,
    sync_state: &Arc<RwLock<NeighborSyncState>>,
    recent_provers: &Arc<RwLock<RecentProvers>>,
    config: &ReplicationConfig,
) {
    match result {
        AuditTickResult::Passed {
            challenged_peer,
            keys_checked,
        } => {
            protocol::record_audit_pass(protocol::AuditOutcomeKind::Subtree);
            debug!("Audit passed for {challenged_peer} ({keys_checked} keys)");
            // Peer responded normally — clear the active bootstrap claim while
            // retaining history so a later claim is treated as repeated abuse.
            {
                let mut state = sync_state.write().await;
                state.clear_active_bootstrap_claim(challenged_peer);
            }
            p2p_node
                .report_trust_event(
                    challenged_peer,
                    TrustEvent::ApplicationSuccess(REPLICATION_TRUST_WEIGHT),
                )
                .await;
        }
        AuditTickResult::Failed { evidence } => {
            if let FailureEvidence::AuditFailure {
                challenged_peer,
                confirmed_failed_keys,
                summary,
                reason,
                ..
            } = evidence
            {
                protocol::record_audit_fail(protocol::AuditOutcomeKind::Subtree, reason);
                // Rich diagnostics (from main's audit-failure logging) + the
                // first-failed-key correlation handle.
                let first_failed_key = first_failed_key_label(confirmed_failed_keys);
                error!(
                    "Audit failure for {challenged_peer}: reason={reason:?}, confirmed_failed_keys={}, challenged_keys={}, absent_keys={}, digest_mismatch_keys={}, first_failed_key={first_failed_key}",
                    confirmed_failed_keys.len(),
                    summary.challenged_keys,
                    summary.absent_keys,
                    summary.digest_mismatch_keys,
                );
                // Route the side effects through the subtree-only failure path.
                // Responsible-chunk `AuditChallenge` handling intentionally uses
                // its own old immediate-penalty handler below.
                handle_subtree_failed_audit(
                    challenged_peer,
                    confirmed_failed_keys.len(),
                    reason,
                    p2p_node,
                    sync_state,
                    recent_provers,
                )
                .await;
            }
        }
        AuditTickResult::BootstrapClaim { peer } => {
            // Gap 6: BootstrapClaimAbuse grace period in audit path.
            // Separate state mutation from network I/O to avoid holding the
            // write lock across report_trust_event.
            let should_report = {
                let now = Instant::now();
                let mut state = sync_state.write().await;
                match state.observe_bootstrap_claim(*peer, now, config.bootstrap_claim_grace_period)
                {
                    BootstrapClaimObservation::WithinGrace { .. } => {
                        debug!("Audit: peer {peer} claims bootstrapping (within grace period)");
                        false
                    }
                    BootstrapClaimObservation::PastGrace { first_seen } => {
                        warn!(
                            "Audit: peer {peer} claiming bootstrap past grace period \
                             ({:?} > {:?}), reporting abuse",
                            now.duration_since(first_seen),
                            config.bootstrap_claim_grace_period,
                        );
                        true
                    }
                    BootstrapClaimObservation::Repeated { first_seen } => {
                        warn!(
                            "Audit: peer {peer} repeated bootstrap claim after previously \
                             stopping; first claim was {:?} ago, reporting abuse",
                            now.duration_since(first_seen),
                        );
                        true
                    }
                }
            };
            if should_report {
                p2p_node
                    .report_trust_event(
                        peer,
                        TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                    )
                    .await;
            }
        }
        AuditTickResult::Idle | AuditTickResult::InsufficientKeys => {}
    }
}

/// Whether a confirmed audit failure with this reason clears the peer's active
/// bootstrap claim. A `Timeout` does not (the peer may still be legitimately
/// bootstrapping); every confirmed storage-integrity reason does.
///
/// Responsible-chunk `AuditChallenge` failures use this directly: timeouts keep
/// the bootstrap claim, matching the pre-ADR-0002 behaviour. Whether a timeout
/// is also *penalised* is a separate question — see
/// [`audit_failure_reports_trust_penalty`].
fn audit_failure_clears_bootstrap_claim(reason: &AuditFailureReason) -> bool {
    !matches!(reason, AuditFailureReason::Timeout)
}

/// Whether an audit failure with this reason reports an application trust event
/// at [`AUDIT_FAILURE_TRUST_WEIGHT`](config::AUDIT_FAILURE_TRUST_WEIGHT).
///
/// ROLLOUT GATE — see [`GRACE_POSSESSION_AUDIT_TIMEOUTS`]. While that gate is
/// set, a `Timeout` on the digest lanes is graced, because a peer on the other
/// side of the possession-audit protocol move never answers and its silence is
/// not evidence about its storage. Every other reason is a confirmed failure and
/// is always penalised. When the gate is removed this becomes `true` for every
/// reason, restoring the unconditional penalty.
///
/// [`GRACE_POSSESSION_AUDIT_TIMEOUTS`]: config::GRACE_POSSESSION_AUDIT_TIMEOUTS
fn audit_failure_reports_trust_penalty(reason: &AuditFailureReason) -> bool {
    if config::GRACE_POSSESSION_AUDIT_TIMEOUTS {
        !matches!(reason, AuditFailureReason::Timeout)
    } else {
        true
    }
}

/// Handle the result of a responsible-chunk audit tick (audit #2): emit trust
/// events and manage bootstrap-claim state.
///
/// This is intentionally separate from the subtree audit result handler. A
/// responsible-chunk `AuditChallenge` `Failed` result reports
/// `ApplicationFailure` immediately for every reason, including `Timeout`,
/// restoring the pre-ADR-0002 behaviour.
async fn handle_audit_result(
    result: &AuditTickResult,
    p2p_node: &Arc<P2PNode>,
    sync_state: &Arc<RwLock<NeighborSyncState>>,
    config: &ReplicationConfig,
) {
    match result {
        AuditTickResult::Passed {
            challenged_peer,
            keys_checked,
        } => {
            protocol::record_audit_pass(protocol::AuditOutcomeKind::Responsible);
            debug!("Audit passed for {challenged_peer} ({keys_checked} keys)");
            {
                let mut state = sync_state.write().await;
                state.clear_active_bootstrap_claim(challenged_peer);
            }
            p2p_node
                .report_trust_event(
                    challenged_peer,
                    TrustEvent::ApplicationSuccess(REPLICATION_TRUST_WEIGHT),
                )
                .await;
        }
        AuditTickResult::Failed { evidence } => {
            if let FailureEvidence::AuditFailure {
                challenged_peer,
                confirmed_failed_keys,
                summary,
                reason,
                ..
            } = evidence
            {
                protocol::record_audit_fail(protocol::AuditOutcomeKind::Responsible, reason);
                let first_failed_key = first_failed_key_label(confirmed_failed_keys);
                error!(
                    "Audit failure for {challenged_peer}: reason={reason:?}, confirmed_failed_keys={}, challenged_keys={}, absent_keys={}, digest_mismatch_keys={}, first_failed_key={first_failed_key}",
                    confirmed_failed_keys.len(),
                    summary.challenged_keys,
                    summary.absent_keys,
                    summary.digest_mismatch_keys,
                );
                if audit_failure_clears_bootstrap_claim(reason) {
                    let mut state = sync_state.write().await;
                    state.clear_active_bootstrap_claim(challenged_peer);
                } else {
                    debug!("Audit timeout for {challenged_peer}; retaining active bootstrap claim");
                }
                if audit_failure_reports_trust_penalty(reason) {
                    p2p_node
                        .report_trust_event(
                            challenged_peer,
                            TrustEvent::ApplicationFailure(config::AUDIT_FAILURE_TRUST_WEIGHT),
                        )
                        .await;
                } else {
                    debug!(
                        "Audit timeout for {challenged_peer} graced during the possession-audit \
                         protocol rollout (no confirmed-failure penalty)"
                    );
                }
            }
        }
        AuditTickResult::BootstrapClaim { peer } => {
            let should_report = {
                let now = Instant::now();
                let mut state = sync_state.write().await;
                match state.observe_bootstrap_claim(*peer, now, config.bootstrap_claim_grace_period)
                {
                    BootstrapClaimObservation::WithinGrace { .. } => {
                        debug!("Audit: peer {peer} claims bootstrapping (within grace period)");
                        false
                    }
                    BootstrapClaimObservation::PastGrace { first_seen } => {
                        warn!(
                            "Audit: peer {peer} claiming bootstrap past grace period \
                             ({:?} > {:?}), reporting abuse",
                            now.duration_since(first_seen),
                            config.bootstrap_claim_grace_period,
                        );
                        true
                    }
                    BootstrapClaimObservation::Repeated { first_seen } => {
                        warn!(
                            "Audit: peer {peer} repeated bootstrap claim after previously \
                             stopping; first claim was {:?} ago, reporting abuse",
                            now.duration_since(first_seen),
                        );
                        true
                    }
                }
            };
            if should_report {
                p2p_node
                    .report_trust_event(
                        peer,
                        TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                    )
                    .await;
            }
        }
        AuditTickResult::Idle | AuditTickResult::InsufficientKeys => {}
    }
}

/// Whether a confirmed audit failure with this reason should revoke the
/// peer's `recent_provers` holder credit immediately (v12 §6).
///
/// `true` for any reason where the peer actually answered (or admitted
/// it cannot): `DigestMismatch`, `KeyAbsent`, `Rejected` ("missing
/// bytes for committed key"), `MalformedResponse` — these prove the
/// peer no longer holds what it committed to, so it must not keep
/// holder credit for the proof TTL. `false` for `Timeout`: a single
/// dropped packet must not strip an honest peer; the 40-min TTL is the
/// deliberate liveness cushion there.
fn audit_failure_revokes_holder_credit(reason: &AuditFailureReason) -> bool {
    !matches!(reason, AuditFailureReason::Timeout)
}

/// Apply the holder-credit revocation decision for a confirmed audit
/// failure. Pure over `RecentProvers` so the handler wiring is unit-
/// testable without a live `P2PNode`: the production `Failed` arm of
/// `handle_subtree_audit_result` calls exactly this.
fn apply_audit_failure_credit_revocation(
    provers: &mut RecentProvers,
    challenged_peer: &PeerId,
    reason: &AuditFailureReason,
) {
    if audit_failure_revokes_holder_credit(reason) {
        provers.forget_peer(challenged_peer);
    }
}

// `admit_bootstrap_hints` was consolidated into `admit_and_queue_hints`.

// ---------------------------------------------------------------------------
// Storage-bound audit (ADR-0002) — gossip trigger + auditor-side ingestion
// ---------------------------------------------------------------------------

/// State the gossip-audit trigger needs to spawn an audit. Bundled so the
/// message handler passes one value instead of a long argument list; all
/// fields are cheap `Arc` clones.
#[derive(Clone)]
struct GossipAuditTrigger {
    p2p_node: Arc<P2PNode>,
    config: Arc<ReplicationConfig>,
    recent_provers: Arc<RwLock<RecentProvers>>,
    sync_state: Arc<RwLock<NeighborSyncState>>,
    /// Shared "an audit actually launched" cooldown, consulted by BOTH the
    /// gossip-lottery path and the monetized first-audit scheduler. Stamped
    /// only when a real audit is about to be sent — never by a losing lottery
    /// ticket — so gossip traffic alone can never suppress a paid first audit.
    cooldown: Arc<RwLock<HashMap<PeerId, Instant>>>,
    /// Gossip-private lottery attempt window: stamped on every roll (win or
    /// lose) so a gossip flood cannot re-roll the lottery within the window.
    /// The first-audit scheduler never reads this map.
    lottery_attempts: Arc<RwLock<HashMap<PeerId, Instant>>>,
}

/// What a gossip ingest yields for the audit trigger: the commitment hash to
/// pin and the `key_count` needed to size the response deadline from the actual
/// `ceil(sqrt(N))` subtree (ADR-0002). Returned on every VALID gossip (changed
/// or not) so a stable-keyset node stays auditable — not just on its first
/// commitment.
#[derive(Debug, Clone, Copy)]
struct AuditTarget {
    pin_hash: [u8; 32],
    key_count: u32,
}

/// ADR-0004: a commitment that backed a payment, surfaced by the payment
/// verifier's cross-check so it can receive a **deterministic first audit**.
///
/// Sent from the verifier to the replication engine's first-audit drainer. The
/// drainer dedups by `pin` (a pin gets one deterministic first audit; later
/// audits of the same peer revert to the gossip lottery), orders most-recently-
/// monetized first, and runs the same `run_subtree_audit` under the same
/// per-peer cooldown and concurrency caps — only the lottery is bypassed.
#[derive(Debug, Clone, Copy)]
pub struct MonetizedPinEvent {
    /// The peer whose commitment backed the payment.
    pub peer: PeerId,
    /// The pinned commitment hash.
    pub pin: [u8; 32],
    /// The committed key count (sizes the audit deadline).
    pub key_count: u32,
    /// The accused's own SIGNED quote timestamp. The first-audit drainer skips a
    /// pin whose quote is older than the answerability window (ADR-0004 A1
    /// guardrail A): with grace removed, challenging an aged-out pin would
    /// false-convict, so a stale client-forwarded quote must not trigger an audit.
    pub quote_ts: SystemTime,
}

/// Per-peer audit cooldown check-and-stamp (ADR-0002 "occasional surprise
/// exams, keeps load low"). Returns `true` if `peer` may be audited now (and
/// stamps `now`), `false` if it was audited within
/// `AUDIT_ON_GOSSIP_COOLDOWN_SECS`. Bounds the map under a flood of distinct
/// peers. Pure over the passed map so the flood/cooldown behaviour is testable
/// without a live node: a burst of gossips from one peer yields at most one
/// `true` per cooldown window.
fn cooldown_allows_audit(map: &mut HashMap<PeerId, Instant>, peer: &PeerId, now: Instant) -> bool {
    let cooldown = Duration::from_secs(config::AUDIT_ON_GOSSIP_COOLDOWN_SECS);
    let known = match map.get(peer) {
        Some(&last) => {
            if now.saturating_duration_since(last) < cooldown {
                return false;
            }
            true
        }
        None => false,
    };
    // Bound the map under churn like its siblings (drop the oldest stamp) before
    // admitting a brand-new peer.
    if !known && map.len() >= MAX_LAST_COMMITMENT_BY_PEER {
        if let Some(victim) = map.iter().min_by_key(|(_, &ts)| ts).map(|(p, _)| *p) {
            map.remove(&victim);
        }
    }
    map.insert(*peer, now);
    true
}

/// Read-only companion to [`cooldown_allows_audit`]: whether `peer` is OUTSIDE
/// its cooldown at `now`, WITHOUT stamping. Used by the first-audit reserve gate
/// (ADR-0004 Amendment 2 E′) to avoid reserving a peer that a recent audit
/// already covered; the authoritative check-and-stamp still runs at promotion,
/// so this is only an optimization and never the security boundary.
fn cooldown_would_allow(map: &HashMap<PeerId, Instant>, peer: &PeerId, now: Instant) -> bool {
    let cooldown = Duration::from_secs(config::AUDIT_ON_GOSSIP_COOLDOWN_SECS);
    map.get(peer).map_or(true, |&last| {
        now.saturating_duration_since(last) >= cooldown
    })
}

/// The gossip-audit launch decision in ONE place so the ordering is shared
/// between production and its test (ADR-0002 "occasional surprise exams").
///
/// Order matters and is the security-relevant property. Gate 1 checks-and-stamps
/// the gossip-PRIVATE `attempts` window, win or lose: if the lottery were
/// sampled first, a gossip flood would re-roll it on every message until one
/// won, multiplying audits, so each peer gets at most one lottery roll per
/// window regardless of how often it gossips. Gate 3 checks-and-stamps the
/// SHARED `launched` cooldown — the map the monetized first-audit scheduler
/// also consults — only after a WIN, i.e. only when a real audit is about to be
/// sent. A losing ticket must never stamp `launched`: no challenge went on the
/// wire, so it must not defer a paid first audit (repeatable losses could
/// otherwise hold a monetized pin past its answerability window). Production
/// calls this with `lottery_wins = gen_bool(AUDIT_ON_GOSSIP_PROBABILITY)`; the
/// test calls it with a deterministic `lottery_wins`, so a reorder regression
/// here fails the test.
fn audit_launch_decision(
    attempts: &mut HashMap<PeerId, Instant>,
    launched: &mut HashMap<PeerId, Instant>,
    peer: &PeerId,
    now: Instant,
    lottery_wins: bool,
) -> bool {
    // Gate 1: lottery-attempt window check-and-stamp (consumes the attempt
    // window even on a loss; private to the gossip path).
    if !cooldown_allows_audit(attempts, peer, now) {
        return false;
    }
    // Gate 2: the probability lottery. A loss stops here and stamps nothing
    // shared.
    if !lottery_wins {
        return false;
    }
    // Gate 3: the shared actual-audit cooldown (a recent real audit from
    // either path still suppresses this launch), stamped only on launch.
    cooldown_allows_audit(launched, peer, now)
}

/// On a peer's *changed* gossiped commitment, maybe launch a subtree audit
/// (ADR-0002): fire with probability `AUDIT_ON_GOSSIP_PROBABILITY`, subject to a
/// per-peer cooldown, pinned to the just-ingested root. Detached so gossip
/// handling is never blocked on a network round-trip.
async fn maybe_trigger_gossip_audit(
    trigger: &GossipAuditTrigger,
    peer: &PeerId,
    target: AuditTarget,
) {
    // The launch decision (attempt-window, lottery, shared-cooldown ordering)
    // lives in the pure `audit_launch_decision` so the ordering is shared with
    // its test. Sample the lottery here, then let the helper apply the gates.
    let now = Instant::now();
    let lottery_wins = rand::thread_rng().gen_bool(config::AUDIT_ON_GOSSIP_PROBABILITY);
    {
        // Lock order: attempts before the shared cooldown; this is the only
        // place both are held together.
        let mut attempts = trigger.lottery_attempts.write().await;
        let mut launched = trigger.cooldown.write().await;
        if !audit_launch_decision(&mut attempts, &mut launched, peer, now, lottery_wins) {
            return;
        }
    }

    let trigger = trigger.clone();
    let peer = *peer;
    tokio::spawn(async move {
        let credit = storage_commitment_audit::AuditCredit {
            recent_provers: &trigger.recent_provers,
        };
        let result = storage_commitment_audit::run_subtree_audit(
            &trigger.p2p_node,
            &trigger.config,
            &peer,
            target.pin_hash,
            target.key_count,
            Some(&credit),
        )
        .await;
        handle_subtree_audit_result(
            &result,
            &trigger.p2p_node,
            &trigger.sync_state,
            &trigger.recent_provers,
            &trigger.config,
        )
        .await;
    });
}

/// Atomic check-and-stamp of the per-peer commitment sig-verify rate limit.
///
/// Returns `true` if a signature verify is allowed now (and stamps the attempt
/// time), `false` if the peer is within [`COMMITMENT_SIG_VERIFY_MIN_INTERVAL`]
/// of its last attempt. Holds one write lock across the decision so two
/// concurrent ingests from the same peer cannot both pass. Stamps BEFORE the
/// caller's expensive verify so a slow/failed verify still rate-limits the next
/// message. Bounds the map under a flood of distinct peer ids.
async fn sig_verify_rate_limit_ok(
    sig_verify_attempts: &Arc<RwLock<HashMap<PeerId, Instant>>>,
    source: &PeerId,
    now: Instant,
) -> bool {
    let mut attempts = sig_verify_attempts.write().await;
    if let Some(&last) = attempts.get(source) {
        if now.saturating_duration_since(last) < COMMITMENT_SIG_VERIFY_MIN_INTERVAL {
            return false;
        }
    }
    if attempts.len() >= MAX_LAST_COMMITMENT_BY_PEER && !attempts.contains_key(source) {
        if let Some(victim) = attempts.iter().min_by_key(|(_, &ts)| ts).map(|(p, _)| *p) {
            attempts.remove(&victim);
        }
    }
    attempts.insert(*source, now);
    true
}

/// Verify + store an inbound commitment from a gossip peer.
///
/// Called from the inbound `NeighborSyncRequest`/`Response` handlers and
/// the bootstrap-sync loop. Drops the commitment unless all five gates
/// pass:
///   1. `source` is in our DHT routing table (sybil/churn cap).
///   2. `commitment.sender_peer_id == source.as_bytes()` (peer-id
///      binding to the authenticated transport peer).
///   3. `BLAKE3(commitment.sender_public_key) == commitment.sender_peer_id`
///      (the embedded pubkey actually belongs to the claimed identity —
///      saorsa-core derives `PeerId = BLAKE3(pubkey)`).
///   4. `verify_commitment_signature(commitment)` succeeds against the
///      embedded public key. The signed payload binds the pubkey, so an
///      adversary cannot swap the key while keeping the body.
///   5. The cache has room or this is an update for an existing entry
///      (sybil cap, `MAX_LAST_COMMITMENT_BY_PEER`).
///
/// On all-pass, the commitment is stored as the auditor's per-peer
/// "last known commitment" for use as `expected_commitment_hash` in
/// future audits.
///
/// Failures (no commitment / mismatched peer id / bad signature) are
/// silent drops — gossip is best-effort and a malformed commitment from
/// one peer should not affect anything else.
///
/// Returns `Some(AuditTarget)` whenever a VALID commitment was stored (whether
/// or not its root changed), so the caller can run a probabilistic,
/// cooldown-gated subtree audit. Returning on *every* valid gossip — not only
/// changed ones — is deliberate (ADR-0002): a node with a stable key set keeps
/// being auditable, so it cannot pass one audit and then delete data while
/// re-gossiping the same root forever. The cooldown + probability bound the
/// audit frequency. Returns `None` only if the commitment was dropped (failed a
/// gate) or there is nothing to pin.
///
/// Handle a capable peer gossiping `None` (a commitment downgrade).
///
/// A capable peer that previously gossiped a commitment but now gossips `None`
/// is trying to drop off the audit path. Within the answerability window we keep
/// the cached commitment pinned AND return it as an audit target so this gossip
/// still schedules a subtree audit against the peer's last known commitment — if
/// it genuinely dropped the data, the audit fails (there is no periodic tick, so
/// the trigger MUST fire here or the downgrade is never re-challenged).
///
/// But this only holds within the SAME `GOSSIP_ANSWERABILITY_TTL` the responder
/// honours for its own retired commitment: once that elapses since we last
/// received the peer's commitment, an honest peer has legitimately retired that
/// root (its responder side `retire_current`s and lets it age out) and can no
/// longer answer a pin on it. Auditing it past the TTL would manufacture a false
/// failure, so we then forget the cached commitment (keeping the sticky
/// `commitment_capable` bit) and stop pinning it.
async fn handle_commitment_downgrade(
    source: &PeerId,
    last_commitment_by_peer: &Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>>,
) -> Option<AuditTarget> {
    let now = Instant::now();
    let cached = {
        let map = last_commitment_by_peer.read().await;
        map.get(source).and_then(|rec| {
            if !rec.commitment_capable {
                return None;
            }
            let last = rec.last_commitment()?;
            let pin = rec.commitment_hash()?;
            let fresh = now.saturating_duration_since(rec.received_at) < GOSSIP_ANSWERABILITY_TTL;
            Some((pin, last.key_count, fresh))
        })
    };
    match cached {
        Some((pin, key_count, true)) => {
            warn!(
                "ingest_peer_commitment: commitment-capable peer {source} sent None \
                 (downgrade attempt); auditing against its last cached commitment"
            );
            Some(AuditTarget {
                pin_hash: pin,
                key_count,
            })
        }
        Some((_, _, false)) => {
            // Cached commitment has aged past the answerability window — forget
            // it so we stop pinning a root the peer is no longer obliged to
            // answer. Keep `commitment_capable` (sticky). Re-check freshness
            // UNDER the write lock (compare-and-clear): a concurrent valid gossip
            // from this peer may have refreshed `received_at` in the gap between
            // our read and write locks; if so, leave its fresh commitment intact.
            if let Some(rec) = last_commitment_by_peer.write().await.get_mut(source) {
                let still_stale =
                    now.saturating_duration_since(rec.received_at) >= GOSSIP_ANSWERABILITY_TTL;
                if still_stale {
                    rec.clear_commitment();
                    debug!(
                        "ingest_peer_commitment: capable peer {source} sent None and its cached \
                         commitment aged past the answerability TTL; forgetting it"
                    );
                }
            }
            None
        }
        None => None,
    }
}

async fn ingest_peer_commitment(
    source: &PeerId,
    commitment: Option<&StorageCommitment>,
    p2p_node: &Arc<P2PNode>,
    last_commitment_by_peer: &Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>>,
    ever_capable_peers: &Arc<RwLock<HashSet<PeerId>>>,
    sig_verify_attempts: &Arc<RwLock<HashMap<PeerId, Instant>>>,
) -> Option<AuditTarget> {
    let Some(c) = commitment else {
        return handle_commitment_downgrade(source, last_commitment_by_peer).await;
    };
    // RT-membership gate: only accept commitments from peers in our
    // routing table. Off-RT senders (sybils, drive-by relays) cannot
    // populate the cache, which closes the hole where a flood of
    // off-RT identities could fill the cap and evict honest
    // peers. The neighbor-sync request handler applies the same gate
    // before admitting inbound replication hints (see neighbor_sync.rs
    // `sender_in_rt`); we mirror that policy here for the commitment
    // piggyback.
    if !p2p_node.dht_manager().is_in_routing_table(source).await {
        debug!("ingest_peer_commitment: source {source} not in routing table (dropped)");
        return None;
    }
    // Peer-id binding: the commitment's claimed sender must match the
    // authenticated transport peer (`source`). Defeats relay/replay
    // and also pins which embedded public key we are about to verify
    // against — the verify itself trusts the embedded key, so the
    // peer-id binding is the link to a real identity.
    if &c.sender_peer_id != source.as_bytes() {
        warn!(
            "ingest_peer_commitment: sender_peer_id mismatch from {source} \
             (dropped, possible relay attempt)"
        );
        return None;
    }
    // Peer-id to embedded-pubkey binding: saorsa-core derives PeerId as
    // BLAKE3(pubkey_bytes). Without this check, a responder could sign
    // with a throwaway key they own and lie about which identity it
    // belongs to (the embedded-key signature would verify trivially).
    let derived_peer_id = *blake3::hash(&c.sender_public_key).as_bytes();
    if derived_peer_id != c.sender_peer_id {
        warn!(
            "ingest_peer_commitment: embedded pubkey does not hash to claimed peer_id for \
             {source} (dropped, throwaway-key attack)"
        );
        return None;
    }
    // §2 step 3 + §11 DoS: rate-limit per-peer to at most one ML-DSA
    // signature verify per `COMMITMENT_SIG_VERIFY_MIN_INTERVAL`. A
    // sybil/RT-membership-bypassing peer that flooded valid-looking
    // gossip would otherwise burn CPU on every message. The rate
    // limit is checked AFTER cheap structural gates (RT, peer-id
    // binding, pubkey-binding) and BEFORE the expensive sig verify.
    //
    // Tracked in `sig_verify_attempts` (separate from
    // last_commitment_by_peer) so EVERY attempt — successful or not —
    // bumps the rate-limit clock. Reading only from PeerCommitmentRecord
    // would skip the cap for peers we've never successfully verified,
    // letting a flood of invalid-but-structurally-plausible gossips
    // burn CPU.
    let now = Instant::now();
    if !sig_verify_rate_limit_ok(sig_verify_attempts, source, now).await {
        debug!(
            "ingest_peer_commitment: rate-limited sig verify from {source} \
             (< {COMMITMENT_SIG_VERIFY_MIN_INTERVAL:?} since last attempt); dropped"
        );
        return None;
    }
    // Signature verify, using the public key embedded in the commitment
    // itself. The pubkey is bound by the signature payload (see
    // commitment_signed_payload) so an adversary cannot keep the body
    // and swap the key to one they hold the secret for.
    if !crate::replication::commitment::verify_commitment_signature(c) {
        warn!(
            "ingest_peer_commitment: signature did not verify under embedded key for {source} \
             (dropped, forged commitment)"
        );
        return None;
    }
    // The new commitment's hash, used to store and to pin for the audit target.
    let new_hash = commitment_hash(c);
    let mut map = last_commitment_by_peer.write().await;
    // Sybil/churn cap: if we're at the hard cap AND this is a new peer,
    // evict an arbitrary existing entry to make room. Updates for peers
    // already in the map are always accepted (they replace, not grow).
    if map.len() >= MAX_LAST_COMMITMENT_BY_PEER && !map.contains_key(source) {
        // Drop one arbitrary entry. HashMap iter order is random which
        // is fine — over time PeerRemoved cleanup keeps the working set
        // anchored on the real RT membership; this cap only fires under
        // active flooding attempts.
        if let Some(victim) = map.keys().next().copied() {
            map.remove(&victim);
            warn!(
                "ingest_peer_commitment: cache full ({MAX_LAST_COMMITMENT_BY_PEER}); \
                 evicted {victim} to admit {source}"
            );
        }
    }
    // Preserve sticky commitment_capable across updates — once true,
    // always true. New entries start with capable = true (we just
    // verified a valid commitment from this peer).
    map.entry(*source)
        .and_modify(|r| {
            // set_commitment refreshes the cached hash (§13) alongside the
            // commitment + received_at so they never drift.
            r.set_commitment(c.clone(), now);
            r.last_sig_verify_at = now;
            r.commitment_capable = true; // sticky-redundant but explicit
        })
        .or_insert_with(|| PeerCommitmentRecord::from_verified(c.clone(), now));
    drop(map);
    // Record the sticky "ever v12-capable" bit in a set independent of
    // `last_commitment_by_peer` (whose entries can be evicted by
    // `PeerRemoved` and the sybil cap). This is what the §3 audit
    // shield and the §6 holder-eligibility closure consult to decide
    // whether the peer is expected to speak v12.
    //
    // Capped at `MAX_EVER_CAPABLE_PEERS` to bound memory under
    // identity-rotation attacks: once full, new entries are refused.
    // Refusal degrades over-cap peers to the behaviour before this set
    // existed (treated as legacy on rejoin), which is not a security
    // regression and preserves the historic set stable.
    {
        let mut set = ever_capable_peers.write().await;
        if set.contains(source) || set.len() < MAX_EVER_CAPABLE_PEERS {
            set.insert(*source);
        } else {
            warn!(
                "ingest_peer_commitment: ever_capable_peers at cap \
                 ({MAX_EVER_CAPABLE_PEERS}); refusing to record {source} as sticky-capable"
            );
        }
    }
    // Return an audit target for EVERY valid stored commitment (changed or
    // not), so the caller's cooldown+probability-gated trigger keeps a
    // stable-keyset peer auditable over time (ADR-0002). Only a serialization
    // failure (new_hash == None, unreachable for a real commitment) yields None.
    new_hash.map(|pin_hash| AuditTarget {
        pin_hash,
        key_count: c.key_count,
    })
}

// ---------------------------------------------------------------------------
// Storage-bound audit (v12) — responder commitment rotation
// ---------------------------------------------------------------------------

/// Reload persisted responder retention at startup (ADR-0004 A1). A missing file
/// is a normal fresh start; a corrupt snapshot is logged and skipped (fail-open
/// LOCALLY — the node re-gossips a fresh root — which never grants a remote grace).
async fn load_commitment_retention(state: &ResponderCommitmentState, path: &Path) {
    let bytes = match tokio::fs::read(path).await {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            debug!(
                "Commitment retention: no snapshot at {} (fresh start)",
                path.display()
            );
            return;
        }
        Err(e) => {
            warn!(
                "Commitment retention: failed to read {}: {e}",
                path.display()
            );
            return;
        }
    };
    if let Some(persisted) = PersistedRetention::from_bytes(&bytes) {
        state.restore(&persisted);
        info!(
            "Commitment retention: reloaded {} slot(s) from {}",
            state.retained_slot_count(),
            path.display()
        );
    } else {
        warn!(
            "Commitment retention: corrupt snapshot at {}; starting with empty retention",
            path.display()
        );
    }
}

/// Persist the responder retention snapshot IF it changed since `last` (ADR-0004
/// A1). Write-on-change keeps frequent gossip-stamp refreshes durable without
/// needless disk writes on idle nodes. On success updates `last` to the bytes
/// written; on a serialization/write error the existing on-disk snapshot is left
/// intact (never truncated).
async fn persist_retention_if_changed(
    state: &ResponderCommitmentState,
    path: &Path,
    last: &mut Option<Vec<u8>>,
) {
    let Some(bytes) = state.snapshot().to_bytes() else {
        warn!("Commitment retention: serialization failed; keeping previous snapshot");
        return;
    };
    if last.as_deref() == Some(bytes.as_slice()) {
        return;
    }
    if write_retention_atomic(path, bytes.clone()).await {
        *last = Some(bytes);
    }
}

/// Durably write `bytes` to `path`: temp file → fsync temp → atomic rename →
/// fsync parent dir (so the rename itself survives a crash). Returns `true` on
/// success. Only the retention-persist loop writes this path, so a fixed temp
/// name is safe.
async fn write_retention_atomic(path: &Path, bytes: Vec<u8>) -> bool {
    let path = path.to_path_buf();
    let res = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::File::open(&tmp)?.sync_all()?;
        std::fs::rename(&tmp, &path)?;
        // Fsync the directory so the rename (the durable-commit point) is not
        // lost on a crash right after it. An empty parent (relative filename)
        // means the current directory.
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    })
    .await;
    match res {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            warn!("Commitment retention: persist failed: {e}");
            false
        }
        Err(e) => {
            warn!("Commitment retention: persist task join failed: {e}");
            false
        }
    }
}

/// Read the current LMDB key set, build + sign a fresh
/// `StorageCommitment`, and rotate it into `state` as the new `current`.
/// The prior `current` is demoted to `previous`; the prior `previous` is
/// dropped (per `ResponderCommitmentState::rotate`).
///
/// For content-addressed chunks (Autonomi's chunk store), `address ==
/// BLAKE3(content)`, so `bytes_hash := key` and we don't have to
/// re-read each chunk's bytes to compute the leaf hash.
///
/// Skips (returns `Ok(())`) if the key set is empty — no commitment to
/// rotate. The auditor side handles "no commitment for this peer" by
/// falling back to the legacy plain-digest audit path.
async fn rebuild_and_rotate_commitment(
    storage: &Arc<LmdbStorage>,
    identity: &Arc<NodeIdentity>,
    state: &Arc<ResponderCommitmentState>,
    p2p: &Arc<P2PNode>,
    config: &Arc<ReplicationConfig>,
) -> Result<()> {
    let stored_keys = storage
        .all_keys()
        .await
        .map_err(|e| Error::Storage(format!("commitment build: read keys: {e}")))?;

    // Commit only to keys we are still RESPONSIBLE for ("want-to-hold"), not
    // everything currently on disk ("hold"). This is the half of the retention
    // contract that lets out-of-range chunks age out: a key that has left our
    // close group is excluded from the NEXT commitment, so once its last gossip
    // ages past GOSSIP_ANSWERABILITY_TTL it falls out of the in-window retained
    // set, `ResponderCommitmentState::is_held` goes false,
    // and the pruner (which until then vetoes its deletion) reclaims it. Without
    // this filter the pruner's reprieve would keep re-committing stale keys
    // forever (the rebuild reads all_keys, so a retained-on-disk key would be
    // re-committed and re-gossiped every rotation — a permanent pin).
    let storage_empty = stored_keys.is_empty();
    let self_id = *p2p.peer_id();
    let mut keys = Vec::with_capacity(stored_keys.len());
    for k in stored_keys {
        if admission::is_responsible(&self_id, &k, p2p, config.close_group_size).await {
            keys.push(k);
        }
    }

    if keys.is_empty() {
        if storage_empty {
            // Storage is genuinely empty — there is nothing to answer for, so
            // drop the previously advertised commitment immediately. Keeping it
            // would leave remote auditors pinning a hash we can never satisfy
            // again (the bytes are gone).
            if state.retained_slot_count() > 0 {
                debug!("Commitment rotation: storage empty, clearing retained slots");
                state.clear_all();
            }
            return Ok(());
        }
        // Bytes are still on disk but no key is currently in range. We must NOT
        // clear retention here: a peer may still be pinning a root we gossiped
        // moments ago and could demand its bytes in a round-2 challenge, which
        // we can still answer (the bytes are present). But we must STOP
        // advertising the stale commitment: retire it so `current()` returns
        // `None` and the gossip-emit sites stop re-emitting and re-stamping it.
        // The retired slot then ages out by its gossip-answerability TTL while
        // remaining answerable for in-flight pins until then. Once it ages out,
        // `is_held` flips false and the pruner reclaims the now-uncommitted,
        // out-of-range chunks. (Calling `age_out` alone would leave `current()`
        // pointing at the stale root, which the gossip loop would keep
        // re-stamping — pinning its keys forever.)
        debug!(
            "Commitment rotation: no responsible keys to commit to; retiring current commitment \
             (stays answerable until its gossip TTL lapses, bytes still on disk)"
        );
        state.retire_current();
        return Ok(());
    }

    // Cap to MAX_COMMITMENT_KEY_COUNT for v12 (responder must not commit
    // to more than the protocol limit; auditor would reject the
    // commitment otherwise).
    let cap = commitment::MAX_COMMITMENT_KEY_COUNT as usize;
    if keys.len() > cap {
        warn!(
            "Commitment rotation: key set ({}) exceeds MAX_COMMITMENT_KEY_COUNT ({}); \
             truncating — investigate as this likely means a misconfiguration",
            keys.len(),
            cap
        );
    }

    // INVARIANT: this module is only used with CONTENT-ADDRESSED chunks,
    // where `key == BLAKE3(content)`, so `bytes_hash := key` and we skip a
    // full chunk re-read per rotation.
    //
    // Consequence to be precise about: because the leaf is `(key, key)`,
    // the Merkle root commits to the SET OF KEYS, not to the bytes. The
    // commitment therefore binds "which keys I claim to hold"; it does NOT
    // by itself prove byte possession. Byte possession is enforced by the
    // round-2 slice audit: a Bao verified slice decoded against the chunk
    // ADDRESS plus a keyed nonced block-tree opening under a fresh per-audit
    // nonce, so a responder that holds the key list but dropped the bytes
    // cannot answer. This is sound ONLY while keys are content addresses;
    // the round-1 verifier enforces `bytes_hash == key` on every audited leaf
    // (`evaluate_subtree_structure`), so a non-content-addressed
    // `(key, bytes_hash)` leaf is rejected rather than letting a byte-less node
    // earn credit for `key`. If this module is ever reused for
    // non-content-addressed records, that `(k, k)` shortcut AND the verifier
    // gate must be replaced with `(key, BLAKE3(bytes))` computed from real bytes.
    let entries: Vec<_> = keys.into_iter().take(cap).map(|k| (k, k)).collect();

    // No-op-rotation guard: compute just the Merkle root from `entries`
    // and compare against the currently-advertised commitment's root.
    // If they match, the key set is unchanged and a new rotation would
    // only swap a randomized ML-DSA signature for a fresh one — same
    // content, different commitment_hash. That invalidates every
    // outstanding `recent_provers` credit on this node across the
    // close group with no security benefit, breaking steady-state
    // quorum liveness on large nodes that can't re-audit every key
    // every rotation interval. Skip the rotation entirely when the
    // tree is unchanged.
    // Build the tree ONCE here (moving `entries`): it serves both the no-op
    // root check below and, if we proceed, the signed commitment via
    // `build_from_tree` (§11 — previously the tree was built here and AGAIN
    // inside `BuiltCommitment::build`).
    let candidate_tree = commitment::MerkleTree::build(entries)
        .map_err(|e| Error::Crypto(format!("commitment tree build: {e}")))?;
    let candidate_root = candidate_tree.root();
    if let Some(current) = state.current() {
        if current.commitment().root == candidate_root {
            debug!(
                "Commitment rotation: key set unchanged (root={}); skipping no-op re-sign",
                hex::encode(candidate_root)
            );
            // Even though we skip re-signing (to avoid invalidating holder
            // credit), retention must still advance on the wall clock: a
            // previously-gossiped commitment that holds a now-out-of-range key
            // must be able to age out of the answerability window even when the
            // committed key set is frozen here for many rotations. Without this,
            // the no-op guard would pin a stale slot — and its key — forever.
            state.age_out();
            return Ok(());
        }
    }

    let sk_bytes = identity.secret_key_bytes().to_vec();
    let sk = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &sk_bytes)
        .map_err(|e| Error::Crypto(format!("commitment build: load sk: {e}")))?;
    let pk_bytes = identity.public_key().as_bytes().to_vec();
    let peer_id_bytes = *p2p.peer_id().as_bytes();

    let built = commitment_state::BuiltCommitment::build_from_tree(
        candidate_tree,
        &peer_id_bytes,
        &sk,
        &pk_bytes,
    )
    .map_err(|e| Error::Crypto(format!("commitment build: {e}")))?;

    let hash = hex::encode(built.hash());
    let key_count = built.commitment().key_count;
    state.rotate(built);
    info!("Storage commitment rotated: hash={hash} key_count={key_count}");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use super::{
        apply_audit_failure_credit_revocation, audit_failure_clears_bootstrap_claim,
        audit_failure_revokes_holder_credit, audit_launch_decision, coalesce_first_audit_event,
        config, cooldown_allows_audit, first_audit_count_jump, first_audit_terminal_outcome,
        first_failed_key_label, fresh_offer_payment_context, paid_notify_payment_context,
        quote_answerable_through_nominal_jitter, quote_within_audit_window, FirstAuditLimiter,
        FirstAuditObservability, FirstAuditQueueOutcome, FirstAuditScheduler,
        FirstAuditTerminalOutcome, LimiterVerdict, MonetizedPinEvent,
        FIRST_AUDIT_SEND_LATENCY_SLACK, MONETIZED_AUDIT_SKEW_MARGIN,
    };
    use crate::payment::VerificationContext;
    use crate::replication::audit::AuditTickResult;
    use crate::replication::commitment_state::GOSSIP_ANSWERABILITY_TTL;
    use crate::replication::recent_provers::RecentProvers;
    use crate::replication::types::{AuditFailureReason, FailureEvidence};
    use lru::LruCache;
    use saorsa_core::identity::PeerId;
    use std::collections::HashMap;
    use std::num::NonZeroUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;
    use std::time::Instant;
    use std::time::SystemTime;

    #[test]
    fn match_replication_protocol_accepts_both_ids_bare_and_rr() {
        // Core id, bare gossip form and /rr/ request-response form.
        assert_eq!(
            match_replication_protocol(REPLICATION_PROTOCOL_ID),
            Some((REPLICATION_PROTOCOL_ID, false))
        );
        assert_eq!(
            match_replication_protocol(&format!("{RR_PREFIX}{REPLICATION_PROTOCOL_ID}")),
            Some((REPLICATION_PROTOCOL_ID, true))
        );
        // Subtree-audit id, both forms.
        assert_eq!(
            match_replication_protocol(SUBTREE_AUDIT_PROTOCOL_ID),
            Some((SUBTREE_AUDIT_PROTOCOL_ID, false))
        );
        assert_eq!(
            match_replication_protocol(&format!("{RR_PREFIX}{SUBTREE_AUDIT_PROTOCOL_ID}")),
            Some((SUBTREE_AUDIT_PROTOCOL_ID, true))
        );
        // Possession-audit id, both forms.
        assert_eq!(
            match_replication_protocol(POSSESSION_AUDIT_PROTOCOL_ID),
            Some((POSSESSION_AUDIT_PROTOCOL_ID, false))
        );
        assert_eq!(
            match_replication_protocol(&format!("{RR_PREFIX}{POSSESSION_AUDIT_PROTOCOL_ID}")),
            Some((POSSESSION_AUDIT_PROTOCOL_ID, true))
        );
        // Foreign topics (incl. a bare /rr/ and an unrelated protocol) don't match.
        assert_eq!(match_replication_protocol("autonomi.ant.dht.v1"), None);
        assert_eq!(match_replication_protocol(RR_PREFIX), None);
        assert_eq!(
            match_replication_protocol("autonomi.ant.replication.v3"),
            None
        );
    }

    // The receive guard drops a body whose family disagrees with the id it rode:
    // subtree-audit bodies only on the subtree id, possession-audit bodies only on
    // the possession id, core bodies only on the core id. This is what stops a
    // mixed-version peer's message from being honoured on the wrong handler after
    // a postcard misdecode. The test drives the SAME `body_matches_protocol` the
    // production guard uses, over real bodies, so a regression in the rule fails
    // here.
    #[test]
    fn body_matches_protocol_is_symmetric_over_real_bodies() {
        use crate::replication::protocol::{
            AuditChallenge, FreshReplicationOffer, ReplicationMessageBody, SubtreeSliceChallenge,
        };
        // A subtree-audit body (models a v2 SubtreeByteChallenge, which decodes to
        // this variant 13 under the new enum), a possession-audit body, and a
        // core body.
        let audit = ReplicationMessageBody::SubtreeSliceChallenge(SubtreeSliceChallenge {
            challenge_id: 1,
            nonce: [0u8; 32],
            challenged_peer_id: [0u8; 32],
            expected_commitment_hash: [0u8; 32],
            openings: vec![],
        });
        let possession = ReplicationMessageBody::AuditChallenge(AuditChallenge {
            challenge_id: 1,
            nonce: [0u8; 32],
            challenged_peer_id: [0u8; 32],
            keys: vec![[0u8; 32]],
        });
        let core = ReplicationMessageBody::FreshReplicationOffer(FreshReplicationOffer {
            key: [0u8; 32],
            data: vec![],
            proof_of_payment: vec![],
        });
        // Correct routing is kept.
        assert!(body_matches_protocol(&audit, SUBTREE_AUDIT_PROTOCOL_ID));
        assert!(body_matches_protocol(
            &possession,
            POSSESSION_AUDIT_PROTOCOL_ID
        ));
        assert!(body_matches_protocol(&core, REPLICATION_PROTOCOL_ID));
        // Every cross-routing is dropped. In particular an older peer's
        // possession audit arriving on the shared core id is dropped rather than
        // answered with a digest from a different generation, which would score
        // as a confirmed mismatch against an honest peer.
        for (body, wrong) in [
            (&audit, REPLICATION_PROTOCOL_ID),
            (&audit, POSSESSION_AUDIT_PROTOCOL_ID),
            (&possession, REPLICATION_PROTOCOL_ID),
            (&possession, SUBTREE_AUDIT_PROTOCOL_ID),
            (&core, SUBTREE_AUDIT_PROTOCOL_ID),
            (&core, POSSESSION_AUDIT_PROTOCOL_ID),
        ] {
            assert!(
                !body_matches_protocol(body, wrong),
                "body must not be accepted on {wrong}"
            );
        }

        // Send and receive must agree. A RESPONSE is routed by the same rule, so
        // the id a body is sent on is always an id the peer's guard accepts.
        // Before this was shared, possession responses went out on the core id
        // and only worked because saorsa-core correlates RR replies by
        // (peer, msg_id) rather than by protocol name — a bare possession
        // response was dropped by the receiving guard.
        for (body, expected) in [
            (&audit, SUBTREE_AUDIT_PROTOCOL_ID),
            (&possession, POSSESSION_AUDIT_PROTOCOL_ID),
            (&core, REPLICATION_PROTOCOL_ID),
        ] {
            assert_eq!(
                response_protocol_for(body),
                expected,
                "a response must be sent on the family's own id"
            );
            assert!(
                body_matches_protocol(body, response_protocol_for(body)),
                "the id we send on must be one the receive guard accepts"
            );
        }

        // The possession RESPONSE body (not just the challenge) routes to the
        // possession id too — that is the direction that was actually wrong.
        let possession_response = ReplicationMessageBody::AuditResponse(
            crate::replication::protocol::AuditResponse::Digests {
                challenge_id: 1,
                digests: vec![[0u8; 32]],
            },
        );
        assert_eq!(
            response_protocol_for(&possession_response),
            POSSESSION_AUDIT_PROTOCOL_ID
        );
    }

    fn test_peer(b: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = b;
        PeerId::from_bytes(bytes)
    }

    // The heavy round-1 limiter enforces the per-peer rate cooldown
    // and single-use round-1 → round-2 sessions.
    #[tokio::test]
    async fn subtree_round1_limiter_cooldown_and_single_use_session() {
        let limiter = SubtreeRound1Limiter::new(Duration::from_secs(3600));
        let peer = test_peer(1);

        // First round-1 is admitted; drop the guard so concurrency is free again.
        let guard = limiter.admit(&peer).await;
        assert!(guard.is_some(), "first round-1 admitted");
        drop(guard);
        // A second round-1 within the cooldown is dropped even though the heavy
        // pool now has a free slot — the rate cooldown, not concurrency, blocks it.
        assert!(
            limiter.admit(&peer).await.is_none(),
            "second round-1 within cooldown is rate-dropped"
        );
        // A different peer has its own cooldown.
        assert!(limiter.admit(&test_peer(2)).await.is_some());

        // Session: opened by round 1, consumed exactly once by the matching round 2.
        let hash = [7u8; 32];
        let nonce = [9u8; 32];
        limiter.open_session(peer, 42, hash, nonce).await;
        // Wrong nonce / commitment does not match.
        assert!(!limiter.consume_session(&peer, 42, &hash, &[0u8; 32]).await);
        assert!(!limiter.consume_session(&peer, 42, &[0u8; 32], &nonce).await);
        // A round 2 with no prior round 1 (wrong challenge_id) misses.
        assert!(!limiter.consume_session(&peer, 99, &hash, &nonce).await);
        // The matching round 2 consumes it — and only once (single-use).
        assert!(limiter.consume_session(&peer, 42, &hash, &nonce).await);
        assert!(!limiter.consume_session(&peer, 42, &hash, &nonce).await);
    }

    // The concurrency pool and the per-peer cooldown are both keyed by peer id,
    // so a party holding several identities refills its allowance by rotating
    // between them and can keep the heavy pool busy indefinitely. The work
    // budget is keyed by nothing: it is charged for bytes proved, whoever asked,
    // so a fresh identity is refused exactly like a repeat caller once it is
    // spent. That is the difference between bounding concurrency and bounding
    // sustained work.
    #[tokio::test]
    async fn round1_work_budget_is_not_refilled_by_a_fresh_identity() {
        // Cooldown disabled so only the work budget can refuse anything.
        let limiter = SubtreeRound1Limiter::new(Duration::ZERO);
        assert!(
            limiter.admit(&test_peer(1)).await.is_some(),
            "a node starts with budget in hand so it can serve audits at once"
        );

        // Serve enough proof work to run the balance into debt. Charging exactly
        // the burst would leave it at zero, which the next nanosecond of refill
        // lifts back above the line — the debt is the point.
        limiter
            .charge_work(2 * SUBTREE_ROUND1_WORK_BURST_BYTES)
            .await;

        for id in 2..8u8 {
            assert!(
                limiter.admit(&test_peer(id)).await.is_none(),
                "a never-seen peer must still be refused while the budget is spent"
            );
        }
    }

    // The budget is a rate, not a quota: it comes back on its own, so an honest
    // auditor blocked by a flood is only delayed. Carrying the debt is what
    // prices an expensive proof above a cheap one — without it, a proof reading
    // a maximal subtree would cost no more of the next caller's wait than a
    // one-leaf proof.
    #[test]
    fn round1_work_budget_carries_debt_and_refills_over_time() {
        let now = Instant::now();
        let at = |secs: u64| {
            now.checked_add(Duration::from_secs(secs))
                .unwrap_or_else(Instant::now)
        };
        let mut budget = Round1WorkBudget {
            balance: 0,
            last_refill: now,
        };
        assert!(!budget.has_budget(now), "empty means empty");

        // A proof costing four seconds' worth of refill leaves four seconds of
        // debt, so the wait scales with what was actually served.
        budget.charge(4 * SUBTREE_ROUND1_WORK_REFILL_BYTES_PER_SEC, now);
        assert!(
            !budget.has_budget(at(3)),
            "still in debt three seconds after an over-large proof"
        );
        assert!(
            budget.has_budget(at(5)),
            "the debt is worked off at the refill rate"
        );

        // Idle time does not bank unbounded credit for a later flood.
        budget.refill(at(24 * 60 * 60));
        assert_eq!(
            budget.balance, SUBTREE_ROUND1_WORK_BURST_BYTES,
            "refill is capped at the burst size"
        );
    }

    fn test_key(b: u8) -> crate::ant_protocol::XorName {
        let mut k = [0u8; 32];
        k[0] = b;
        k
    }

    /// Build a round-2 slice challenge matching an open session. `openings` is
    /// empty: these tests exercise admission and session handling only, which
    /// run before any block is opened.
    fn slice_challenge(
        challenge_id: u64,
        commitment_hash: [u8; 32],
        nonce: [u8; 32],
    ) -> protocol::SubtreeSliceChallenge {
        protocol::SubtreeSliceChallenge {
            challenge_id,
            nonce,
            challenged_peer_id: [0u8; 32],
            expected_commitment_hash: commitment_hash,
            openings: Vec::new(),
        }
    }

    // Regression (Copilot, PR #181): a round-2 slice challenge refused at the
    // responder caps MUST NOT burn the single-use round-1 session.
    //
    // The handler used to consume the session first and admit second, so a
    // transient local capacity drop permanently destroyed that audit exchange —
    // every retry hit the `no live round-1 session` path and got `Transient`,
    // even after load cleared. Turning momentary local load into a deterministic
    // round-2 miss costs the responder its whole-slice credit for that round.
    #[tokio::test]
    async fn capacity_refused_slice_challenge_preserves_round1_session() {
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_AUDIT_RESPONSES));
        let inflight = Arc::new(RwLock::new(HashMap::new()));
        let round1 = SubtreeRound1Limiter::new(Duration::ZERO);
        let peer = test_peer(0xB1);
        let (id, hash, nonce) = (77u64, [3u8; 32], [4u8; 32]);
        let challenge = slice_challenge(id, hash, nonce);

        round1.open_session(peer, id, hash, nonce).await;

        // Saturate this peer's share so the next admission must be refused.
        let mut hold = Vec::new();
        for _ in 0..MAX_AUDIT_RESPONSES_PER_PEER {
            match admit_audit_responder(&semaphore, &inflight, &peer).await {
                Ok(guard) => hold.push(guard),
                Err(err) => panic!("unexpected admission failure below the cap: {err:?}"),
            }
        }

        let refused =
            admit_slice_challenge(&semaphore, &inflight, &round1, &peer, &challenge).await;
        assert!(
            matches!(refused, SliceAdmission::Capacity(_)),
            "a saturated peer share must refuse on capacity, not on session"
        );

        // Load clears. The session must have survived the refusal.
        drop(hold);
        let retried =
            admit_slice_challenge(&semaphore, &inflight, &round1, &peer, &challenge).await;
        assert!(
            matches!(retried, SliceAdmission::Admitted(_)),
            "the round-1 session must survive a capacity refusal so the retry succeeds"
        );

        // Still single-use: the successful admission consumed it exactly once.
        drop(retried);
        let replayed =
            admit_slice_challenge(&semaphore, &inflight, &round1, &peer, &challenge).await;
        assert!(
            matches!(replayed, SliceAdmission::NoSession),
            "a consumed session must not be replayable"
        );
    }

    // The permit taken for the session probe is released when the probe misses,
    // so an unsessioned flood cannot pin the responder pool shut.
    #[tokio::test]
    async fn unsessioned_slice_challenge_releases_its_admission_slot() {
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_AUDIT_RESPONSES));
        let inflight = Arc::new(RwLock::new(HashMap::new()));
        let round1 = SubtreeRound1Limiter::new(Duration::ZERO);
        let peer = test_peer(0xB2);
        let challenge = slice_challenge(1, [0u8; 32], [0u8; 32]);

        // Far more unsessioned challenges than the per-peer cap would allow if
        // the slot leaked on the miss path.
        for _ in 0..(MAX_AUDIT_RESPONSES_PER_PEER * 4) {
            let outcome =
                admit_slice_challenge(&semaphore, &inflight, &round1, &peer, &challenge).await;
            assert!(
                matches!(outcome, SliceAdmission::NoSession),
                "no session was ever opened, so every attempt must miss"
            );
        }

        assert_eq!(
            semaphore.available_permits(),
            MAX_CONCURRENT_AUDIT_RESPONSES,
            "every global permit must be returned"
        );
        assert!(
            inflight.read().await.get(&peer).copied().unwrap_or(0) == 0,
            "no per-peer slot may be left occupied"
        );
    }

    // The rollout gate must grace exactly ONE thing — a timeout — and nothing
    // else. A confirmed storage-integrity failure is still penalised while the
    // gate is set, otherwise moving the possession lanes onto their own protocol
    // id would have handed cheating peers an amnesty for the upgrade window.
    //
    // FOLLOW-UP: when `GRACE_POSSESSION_AUDIT_TIMEOUTS` is set to false and the
    // gate deleted, the timeout expectation below flips to `true`. That is the
    // intended end state, and this test is where the flip is reflected.
    #[test]
    fn rollout_gate_graces_only_timeouts() {
        for reason in [
            AuditFailureReason::DigestMismatch,
            AuditFailureReason::KeyAbsent,
            AuditFailureReason::MalformedResponse,
            AuditFailureReason::Rejected,
        ] {
            assert!(
                audit_failure_reports_trust_penalty(&reason),
                "{reason:?} is a confirmed failure and must be penalised even during rollout"
            );
        }
        assert_eq!(
            audit_failure_reports_trust_penalty(&AuditFailureReason::Timeout),
            !config::GRACE_POSSESSION_AUDIT_TIMEOUTS,
            "a timeout is penalised exactly when the rollout gate is off"
        );

        // Holder credit is a separate axis that was already timeout-safe; the
        // gate must not have disturbed it.
        assert!(!audit_failure_revokes_holder_credit(
            &AuditFailureReason::Timeout
        ));
        assert!(audit_failure_revokes_holder_credit(
            &AuditFailureReason::DigestMismatch
        ));
    }

    #[tokio::test]
    async fn audit_responder_admission_reports_per_peer_cap_full() {
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_AUDIT_RESPONSES));
        let inflight = Arc::new(RwLock::new(HashMap::new()));
        let peer = test_peer(0xA1);

        let mut guards = Vec::new();
        for _ in 0..MAX_AUDIT_RESPONSES_PER_PEER {
            match admit_audit_responder(&semaphore, &inflight, &peer).await {
                Ok(guard) => guards.push(guard),
                Err(err) => panic!("unexpected admission failure before peer cap: {err:?}"),
            }
        }

        let Err(err) = admit_audit_responder(&semaphore, &inflight, &peer).await else {
            panic!("admission should fail once per-peer cap is full");
        };
        assert_eq!(err.reason, AuditResponderRejectReason::PerPeerCapFull);
        assert_eq!(err.peer_inflight, MAX_AUDIT_RESPONSES_PER_PEER);
        assert_eq!(err.peer_limit, MAX_AUDIT_RESPONSES_PER_PEER);
        assert_eq!(err.global_limit, MAX_CONCURRENT_AUDIT_RESPONSES);

        drop(guards);
    }

    #[tokio::test]
    async fn audit_responder_admission_reports_global_pool_full() {
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_AUDIT_RESPONSES));
        let inflight = Arc::new(RwLock::new(HashMap::new()));
        let peer = test_peer(0xA2);

        let mut held_global_permits = Vec::new();
        for _ in 0..MAX_CONCURRENT_AUDIT_RESPONSES {
            held_global_permits.push(
                Arc::clone(&semaphore)
                    .try_acquire_owned()
                    .expect("test should be able to exhaust the global pool"),
            );
        }

        let Err(err) = admit_audit_responder(&semaphore, &inflight, &peer).await else {
            panic!("admission should fail once global pool is full");
        };
        assert_eq!(err.reason, AuditResponderRejectReason::GlobalPoolFull);
        assert_eq!(err.global_inflight, MAX_CONCURRENT_AUDIT_RESPONSES);
        assert_eq!(err.global_limit, MAX_CONCURRENT_AUDIT_RESPONSES);
        assert_eq!(err.peer_inflight, 0);
        assert_eq!(err.peer_limit, MAX_AUDIT_RESPONSES_PER_PEER);

        drop(held_global_permits);
    }

    #[test]
    fn first_audit_terminal_outcomes_are_stable() {
        let peer = test_peer(1);
        let passed = AuditTickResult::Passed {
            challenged_peer: peer,
            keys_checked: 1,
        };
        let timed_out = AuditTickResult::Failed {
            evidence: FailureEvidence::AuditFailure {
                challenge_id: 1,
                challenged_peer: peer,
                confirmed_failed_keys: vec![test_key(1)],
                summary: crate::replication::types::AuditFailureSummary::default(),
                reason: AuditFailureReason::Timeout,
            },
        };

        assert_eq!(
            first_audit_terminal_outcome(&passed),
            FirstAuditTerminalOutcome::Passed
        );
        assert_eq!(
            first_audit_terminal_outcome(&timed_out),
            FirstAuditTerminalOutcome::Timeout
        );
        assert_eq!(
            first_audit_terminal_outcome(&AuditTickResult::Idle),
            FirstAuditTerminalOutcome::Idle
        );
        assert_eq!(FirstAuditTerminalOutcome::Passed.as_str(), "passed");
        assert_eq!(FirstAuditTerminalOutcome::Timeout.as_str(), "timeout");
        assert_eq!(FirstAuditTerminalOutcome::Failed.as_str(), "failed");
        assert_eq!(FirstAuditTerminalOutcome::Idle.as_str(), "idle");
        assert_eq!(
            FirstAuditTerminalOutcome::InsufficientKeys.as_str(),
            "insufficient_keys"
        );
        assert_eq!(
            FirstAuditTerminalOutcome::BootstrapClaim.as_str(),
            "bootstrap_claim"
        );
    }

    #[test]
    fn first_audit_coalescing_keeps_highest_count_and_exposes_eviction() {
        let mut pending = LruCache::new(NonZeroUsize::new(1).unwrap());
        let mut rng = StdRng::seed_from_u64(7);
        let peer = test_peer(1);
        let base = MonetizedPinEvent {
            peer,
            pin: [1; 32],
            key_count: 100,
            quote_ts: SystemTime::now(),
        };

        // First insert into an empty slot: Queued.
        assert_eq!(
            coalesce_first_audit_event(&mut pending, base, true, &mut rng),
            FirstAuditQueueOutcome::Queued
        );

        // A strictly LOWER-count same-peer nomination must NOT displace it.
        let lower = MonetizedPinEvent {
            pin: [2; 32],
            key_count: 50,
            ..base
        };
        assert_eq!(
            coalesce_first_audit_event(&mut pending, lower, true, &mut rng),
            FirstAuditQueueOutcome::SuppressedLower
        );
        assert_eq!(
            pending.peek(&peer).map(|e| (e.pin, e.key_count)),
            Some(([1; 32], 100)),
            "the higher-count pin is retained"
        );

        // A HIGHER-count same-peer nomination wins (the inflated pin to audit).
        let higher = MonetizedPinEvent {
            pin: [3; 32],
            key_count: 400,
            ..base
        };
        assert_eq!(
            coalesce_first_audit_event(&mut pending, higher, true, &mut rng),
            FirstAuditQueueOutcome::Coalesced
        );
        assert_eq!(
            pending.peek(&peer).map(|e| (e.pin, e.key_count)),
            Some(([3; 32], 400))
        );

        // EQUAL count: an ordinary (newer) enqueue replaces for freshness...
        let equal_newer = MonetizedPinEvent {
            pin: [4; 32],
            key_count: 400,
            ..base
        };
        assert_eq!(
            coalesce_first_audit_event(&mut pending, equal_newer, true, &mut rng),
            FirstAuditQueueOutcome::Coalesced
        );
        assert_eq!(pending.peek(&peer).map(|e| e.pin), Some([4; 32]));
        // ...but an equal-count OLDER requeue (incoming_is_newer=false) does not.
        let equal_older = MonetizedPinEvent {
            pin: [5; 32],
            key_count: 400,
            ..base
        };
        assert_eq!(
            coalesce_first_audit_event(&mut pending, equal_older, false, &mut rng),
            FirstAuditQueueOutcome::RetainedOnTie
        );
        assert_eq!(pending.peek(&peer).map(|e| e.pin), Some([4; 32]));

        // A different peer at capacity 1 evicts the LRU (a DIFFERENT peer).
        let other_peer = MonetizedPinEvent {
            peer: test_peer(2),
            pin: [6; 32],
            key_count: 100,
            ..base
        };
        assert_eq!(
            coalesce_first_audit_event(&mut pending, other_peer, true, &mut rng),
            FirstAuditQueueOutcome::CapacityEvicted { peer, pin: [4; 32] }
        );
        assert_eq!(pending.len(), 1);
        assert_eq!(pending.peek(&other_peer.peer).map(|e| e.pin), Some([6; 32]));
    }

    // -- ADR-0004 Amendment 2: first-audit launch limiter --------------------

    #[test]
    fn first_audit_limiter_enforces_burst_then_refills() {
        let base = Instant::now();
        let mut limiter = FirstAuditLimiter::new(base);
        let interval = config::FIRST_AUDIT_LAUNCH_INTERVAL;

        // The full burst is admitted back-to-back (distinct peers).
        for i in 0..config::FIRST_AUDIT_BUDGET_BURST {
            let peer = test_peer(u8::try_from(i).expect("small burst"));
            assert_eq!(limiter.assess(&peer, 10, base, 0), LimiterVerdict::Admit);
            limiter.commit_launch(peer, 10, base);
        }
        // Bucket empty: the next distinct peer is deferred, never dropped.
        let extra = test_peer(0xEE);
        assert_eq!(
            limiter.assess(&extra, 10, base, 0),
            LimiterVerdict::RateDeferred
        );

        // One full interval later exactly one token is available again.
        let later = base + interval;
        assert_eq!(limiter.assess(&extra, 10, later, 0), LimiterVerdict::Admit);
        limiter.commit_launch(extra, 10, later);
        let extra2 = test_peer(0xEF);
        assert_eq!(
            limiter.assess(&extra2, 10, later, 0),
            LimiterVerdict::RateDeferred
        );
    }

    #[test]
    fn first_audit_limiter_refill_keeps_fractional_remainder() {
        let base = Instant::now();
        let mut limiter = FirstAuditLimiter::new(base);
        let interval = config::FIRST_AUDIT_LAUNCH_INTERVAL;
        for i in 0..config::FIRST_AUDIT_BUDGET_BURST {
            let peer = test_peer(u8::try_from(i).expect("small burst"));
            assert_eq!(limiter.assess(&peer, 1, base, 0), LimiterVerdict::Admit);
            limiter.commit_launch(peer, 1, base);
        }
        // 1.5 intervals later one token is earned and the half interval is
        // NOT lost to drift...
        let at_1_5 = base + interval + interval / 2;
        let p = test_peer(0xAA);
        assert_eq!(limiter.assess(&p, 1, at_1_5, 0), LimiterVerdict::Admit);
        limiter.commit_launch(p, 1, at_1_5);
        // ...so the next token arrives at 2.0 intervals, not 2.5.
        let at_2_0 = base + interval * 2;
        let q = test_peer(0xAB);
        assert_eq!(limiter.assess(&q, 1, at_2_0, 0), LimiterVerdict::Admit);
    }

    #[test]
    fn first_audit_limiter_inflight_cap_defers_until_slot_frees() {
        let base = Instant::now();
        let mut limiter = FirstAuditLimiter::new(base);
        let peer = test_peer(1);
        assert_eq!(
            limiter.assess(&peer, 1, base, config::FIRST_AUDIT_MAX_INFLIGHT),
            LimiterVerdict::RateDeferred
        );
        // A freed slot admits without any clock movement.
        assert_eq!(
            limiter.assess(&peer, 1, base, config::FIRST_AUDIT_MAX_INFLIGHT - 1),
            LimiterVerdict::Admit
        );
    }

    #[test]
    fn first_audit_limiter_assess_consumes_nothing() {
        let base = Instant::now();
        let mut limiter = FirstAuditLimiter::new(base);
        let peer = test_peer(3);
        // Repeated assessment must not burn budget or stamp the window: only
        // `commit_launch` consumes (the cooldown gate between assess and
        // commit can defer, and that deferral must be free).
        for _ in 0..10 {
            assert_eq!(limiter.assess(&peer, 5, base, 0), LimiterVerdict::Admit);
        }
        for i in 0..config::FIRST_AUDIT_BUDGET_BURST {
            let p = test_peer(0x20 + u8::try_from(i).expect("small burst"));
            assert_eq!(limiter.assess(&p, 5, base, 0), LimiterVerdict::Admit);
            limiter.commit_launch(p, 5, base);
        }
    }

    #[test]
    fn first_audit_limiter_window_dedups_rotated_pins_and_count_jump_overrides() {
        let base = Instant::now();
        let mut limiter = FirstAuditLimiter::new(base);
        let peer = test_peer(7);
        assert_eq!(limiter.assess(&peer, 100, base, 0), LimiterVerdict::Admit);
        limiter.commit_launch(peer, 100, base);

        // A rotated pin with a similar count inside the window is dropped...
        let soon = base + Duration::from_secs(60);
        assert_eq!(
            limiter.assess(&peer, 100, soon, 0),
            LimiterVerdict::WindowDeduped
        );
        // ...even at the exact jump boundary (new*DEN == old*NUM is no jump)...
        assert_eq!(
            limiter.assess(&peer, 150, soon, 0),
            LimiterVerdict::WindowDeduped
        );
        // ...but a >1.5x committed-count jump re-nominates immediately (an
        // inflated sidecar-only pin is invisible to the gossip lottery, so
        // the window must not shield it).
        assert_eq!(limiter.assess(&peer, 151, soon, 0), LimiterVerdict::Admit);

        // Window expiry re-admits an unchanged count.
        let expired = base + config::FIRST_AUDIT_PEER_REAUDIT_INTERVAL;
        assert_eq!(
            limiter.assess(&peer, 100, expired, 0),
            LimiterVerdict::Admit
        );
    }

    #[test]
    fn first_audit_limiter_window_verdict_outranks_empty_budget() {
        // A window-deduped nomination must be DROPPED, not kept pending as
        // rate-deferred, even when the bucket is also empty: re-queuing a
        // suppressed rotation would hold a pending slot for two hours.
        let base = Instant::now();
        let mut limiter = FirstAuditLimiter::new(base);
        let peer = test_peer(9);
        assert_eq!(limiter.assess(&peer, 10, base, 0), LimiterVerdict::Admit);
        limiter.commit_launch(peer, 10, base);
        let other = test_peer(10);
        assert_eq!(limiter.assess(&other, 10, base, 0), LimiterVerdict::Admit);
        limiter.commit_launch(other, 10, base);
        assert_eq!(
            limiter.assess(&peer, 10, base, 0),
            LimiterVerdict::WindowDeduped
        );
    }

    /// ADR-0004 Amendment 2 (E'): the B horizon prefilter rejects a quote that
    /// is answerable now but would age out of the answerability window during
    /// the launch jitter, so scheduling state is only ever committed for a pin
    /// that can still be challenged when it actually sends.
    #[test]
    fn first_audit_horizon_prefilter_boundary() {
        let now = SystemTime::now();
        // C = the too-old cutoff; H = the worst-case send horizon.
        let c = GOSSIP_ANSWERABILITY_TTL.saturating_sub(MONETIZED_AUDIT_SKEW_MARGIN);
        let h = config::FIRST_AUDIT_LAUNCH_JITTER_MAX + FIRST_AUDIT_SEND_LATENCY_SLACK;
        // A quote whose age is exactly C at `now + H` (in the past, since C > H).
        let boundary = now
            .checked_add(h)
            .and_then(|t| t.checked_sub(c))
            .expect("boundary time");

        // In window at `now` (age = C - H < C)...
        assert!(quote_within_audit_window(boundary, now));
        // ...but the horizon prefilter rejects it (age == C at now + H).
        assert!(!quote_answerable_through_nominal_jitter(boundary, now));

        // A hair newer stays answerable through the horizon; a hair older does
        // not. Use 1µs (not 1ns): Windows `SystemTime` has 100ns granularity, so
        // a nanosecond step would round to the same instant there.
        let newer = boundary
            .checked_add(Duration::from_micros(1))
            .expect("newer");
        let older = boundary
            .checked_sub(Duration::from_micros(1))
            .expect("older");
        assert!(quote_answerable_through_nominal_jitter(newer, now));
        assert!(!quote_answerable_through_nominal_jitter(older, now));

        // A quote too far in the FUTURE is rejected at `now`, independent of the
        // horizon.
        let future = now
            .checked_add(MONETIZED_AUDIT_SKEW_MARGIN)
            .and_then(|t| t.checked_add(Duration::from_secs(60)))
            .expect("future");
        assert!(!quote_answerable_through_nominal_jitter(future, now));
    }

    /// ADR-0004 Amendment 2 (E'): a reservation whose AUTHORITATIVE post-jitter
    /// answerability check fails at promotion is fully state-neutral — it stamps
    /// no `first_audited`, no per-peer window, refunds its token, releases its
    /// in-flight slot, does not flip the lane, and does not count a launch — and
    /// a same-peer, same-count successor enqueued DURING the reservation is
    /// retained and becomes the next reservation after the cancel. This is the
    /// exact hole the reviewer flagged: suppression must never outlive a launch
    /// that did not send.
    /// A pending pin that has aged past the answerability horizon must not
    /// suppress a live lower-count nomination for the same peer: under token
    /// starvation no reserve scan ever collects the dead entry, so without the
    /// enqueue-time check the peer would stay unauditable through this path
    /// indefinitely (e.g. after a prune legitimately lowered its key count).
    #[test]
    fn first_audit_stale_incumbent_does_not_suppress_live_lower_count() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mut scheduler = FirstAuditScheduler::new(Instant::now(), test_peer(99));
        let peer = test_peer(1);

        let dead_quote = SystemTime::now()
            .checked_sub(GOSSIP_ANSWERABILITY_TTL)
            .and_then(|t| t.checked_sub(Duration::from_secs(60)))
            .expect("past wall time");
        let stale_high = MonetizedPinEvent {
            peer,
            pin: [1; 32],
            key_count: 400,
            quote_ts: dead_quote,
        };
        scheduler.enqueue(stale_high, &obs);
        assert_eq!(scheduler.pending_len(), 1);

        // A fresh, lower-count nomination (a post-prune commitment).
        let fresh_lower = MonetizedPinEvent {
            peer,
            pin: [2; 32],
            key_count: 100,
            quote_ts: SystemTime::now(),
        };
        scheduler.enqueue(fresh_lower, &obs);

        assert_eq!(scheduler.pending_len(), 1);
        assert_eq!(
            scheduler.pending.peek(&peer).map(|e| e.pin),
            Some([2; 32]),
            "the live nomination replaced the dead incumbent"
        );
        assert_eq!(
            obs.suppressed_lower.load(Ordering::Relaxed),
            0,
            "no self-erasure signal for displacing a dead pin"
        );
        assert_eq!(obs.queued.load(Ordering::Relaxed), 2);
        assert_eq!(
            obs.outside_answerability_window.load(Ordering::Relaxed),
            1,
            "the dead incumbent is accounted as an expiry"
        );
    }

    /// The self-erasure defence is untouched for LIVE incumbents: a lower-count
    /// nomination still loses to an answerable higher-count pending pin.
    #[test]
    fn first_audit_live_incumbent_still_suppresses_lower_count() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mut scheduler = FirstAuditScheduler::new(Instant::now(), test_peer(99));
        let peer = test_peer(1);

        let live_high = MonetizedPinEvent {
            peer,
            pin: [1; 32],
            key_count: 400,
            quote_ts: SystemTime::now(),
        };
        scheduler.enqueue(live_high, &obs);
        let cheaper = MonetizedPinEvent {
            peer,
            pin: [2; 32],
            key_count: 100,
            quote_ts: SystemTime::now(),
        };
        scheduler.enqueue(cheaper, &obs);

        assert_eq!(scheduler.pending_len(), 1);
        assert_eq!(
            scheduler.pending.peek(&peer).map(|e| e.pin),
            Some([1; 32]),
            "the higher-count live pin is retained"
        );
        assert_eq!(obs.suppressed_lower.load(Ordering::Relaxed), 1);
        assert_eq!(obs.outside_answerability_window.load(Ordering::Relaxed), 0);
    }

    /// A fresh nomination for peer `b` (distinct pin per peer).
    fn live_nomination(b: u8) -> MonetizedPinEvent {
        MonetizedPinEvent {
            peer: test_peer(b),
            pin: [b; 32],
            key_count: 100,
            quote_ts: SystemTime::now(),
        }
    }

    /// The pending admission cap must equal the number of usable launches the
    /// token budget can perform inside one answerability window, counted by
    /// SIMULATING the shipped reserve-time predicate instant-by-instant (burst
    /// tokens at age zero, one refill per launch interval), not by repeating
    /// the derivation formula. Any larger and admitted work is guaranteed to
    /// expire unlaunched; any smaller and the budget idles while nominations
    /// are displaced.
    #[test]
    fn first_audit_pending_cap_matches_strict_launch_horizon() {
        let quote_ts = SystemTime::now();
        // Burst launches fire at age zero and must pass the reserve predicate.
        assert!(quote_answerable_through_nominal_jitter(quote_ts, quote_ts));
        let mut usable = usize::try_from(config::FIRST_AUDIT_BUDGET_BURST).expect("burst fits");
        let mut refill = 1u32;
        loop {
            let age = config::FIRST_AUDIT_LAUNCH_INTERVAL * refill;
            let at = quote_ts + age;
            if !quote_answerable_through_nominal_jitter(quote_ts, at) {
                break;
            }
            usable += 1;
            refill += 1;
            assert!(refill < 10_000, "runaway horizon simulation");
        }
        assert_eq!(
            FIRST_AUDIT_PENDING_CAP, usable,
            "cap must match the simulated strict launch horizon"
        );
    }

    /// The pending queue is sized to the launch budget while the dedup set
    /// keeps the commitment-cache bound: shrinking `first_audited` would
    /// forget audited pins and re-admit duplicates.
    #[test]
    fn first_audit_pending_cap_independent_of_dedup_cap() {
        let scheduler = FirstAuditScheduler::new(Instant::now(), test_peer(99));
        assert_eq!(scheduler.pending.cap().get(), FIRST_AUDIT_PENDING_CAP);
        assert_eq!(
            scheduler.first_audited.cap().get(),
            MAX_LAST_COMMITMENT_BY_PEER
        );
    }

    /// Admission beyond the cap displaces exactly one incumbent per overflow
    /// and every displacement is accounted as `capacity_evicted` — the steady
    /// overload signal — never silent loss, and never an admission refusal.
    #[test]
    fn first_audit_admission_beyond_cap_displaces_and_counts() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mut scheduler = FirstAuditScheduler::new(Instant::now(), test_peer(99));
        let overflow: usize = 5;
        let total = FIRST_AUDIT_PENDING_CAP + overflow;

        for i in 0..total {
            let b = u8::try_from(i + 1).expect("test peer count fits u8");
            scheduler.enqueue(live_nomination(b), &obs);
        }

        assert_eq!(scheduler.pending_len(), FIRST_AUDIT_PENDING_CAP);
        assert_eq!(
            obs.capacity_evicted.load(Ordering::Relaxed),
            u64::try_from(overflow).expect("overflow fits u64"),
            "each admission past the cap displaces exactly one entry"
        );
        assert_eq!(
            obs.queued.load(Ordering::Relaxed),
            u64::try_from(total).expect("total fits u64"),
            "displacement is not an admission refusal"
        );
        // Every arrival was admitted (the newest always enters the sample).
        let last = u8::try_from(total).expect("test peer count fits u8");
        assert!(
            scheduler.pending.peek(&test_peer(last)).is_some(),
            "the newest arrival always enters the sample"
        );
    }

    /// The reviewer-demonstrated suppression route: a target followed by an
    /// ordered batch of distinct-peer nominations, all inside one ingress
    /// drain batch (`pending_cap < batch <= FIRST_AUDIT_DRAIN_BATCH`), with
    /// the token bucket EMPTY so no reservation can intervene. Under the old
    /// keep-newest LRU the target was evicted with certainty; under random
    /// displacement its per-overflow eviction probability is `1/cap`, so
    /// across repeated trials the target must survive some runs and be
    /// displaced in others — never deterministically flushed, and every
    /// displacement accounted.
    #[test]
    fn first_audit_ordered_flood_cannot_deterministically_evict_target() {
        let flood: usize = 60; // pending_cap < 60 <= FIRST_AUDIT_DRAIN_BATCH
        assert!(FIRST_AUDIT_PENDING_CAP < flood);
        assert!(flood <= config::FIRST_AUDIT_DRAIN_BATCH);

        let trials = 100u64;
        let mut survived = 0u32;
        let mut evicted = 0u32;
        for trial in 0..trials {
            let obs = Arc::new(FirstAuditObservability::default());
            let mut scheduler = FirstAuditScheduler::new(Instant::now(), test_peer(99));
            // Deterministic per-trial seed: the run is fully reproducible (no
            // flake budget at all) while still exercising 100 distinct
            // eviction sequences.
            scheduler.rng = StdRng::seed_from_u64(trial);
            // Drain the burst tokens so the pre-overflow reservation
            // opportunity cannot fire: this isolates pure retention.
            scheduler.limiter.reserve_token();
            scheduler.limiter.reserve_token();

            let target = test_peer(200);
            scheduler.enqueue(live_nomination(200), &obs);
            for i in 0..flood {
                let b = u8::try_from(i + 1).expect("flood peer fits u8");
                scheduler.enqueue(live_nomination(b), &obs);
            }

            assert_eq!(scheduler.pending_len(), FIRST_AUDIT_PENDING_CAP);
            let overflows = u64::try_from(1 + flood - FIRST_AUDIT_PENDING_CAP)
                .expect("overflow count fits u64");
            assert_eq!(
                obs.capacity_evicted.load(Ordering::Relaxed),
                overflows,
                "every overflow past the cap is accounted, none silent"
            );
            if scheduler.pending.peek(&target).is_some() {
                survived += 1;
            } else {
                evicted += 1;
            }
        }
        // With eviction probability 1/cap per overflow, P(target survives one
        // trial) ~= (1 - 1/31)^30 ~= 0.37, so both outcomes appear across the
        // 100 seeded trials — and the seeds make the split exactly
        // reproducible rather than a (vanishingly small) flake budget.
        assert!(
            survived > 0,
            "target must survive some ordered floods — deterministic eviction \
             would mean keep-newest retention regressed"
        );
        assert!(
            evicted > 0,
            "target must also be displaceable — otherwise overflow is refusing \
             admissions instead of sampling"
        );
    }

    /// With a token AVAILABLE, an overflowing arrival must first give pending
    /// work a launch opportunity: the drainer's pre-overflow reservation pulls
    /// one entry out of the queue, so admission proceeds without any eviction.
    #[test]
    fn first_audit_overflow_reserves_before_destructive_eviction() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mut scheduler = FirstAuditScheduler::new(Instant::now(), test_peer(99));
        let cooldown: HashMap<PeerId, Instant> = HashMap::new();

        for i in 0..FIRST_AUDIT_PENDING_CAP {
            let b = u8::try_from(i + 1).expect("test peer count fits u8");
            scheduler.enqueue(live_nomination(b), &obs);
        }
        let overflowing = live_nomination(250);
        assert!(scheduler.would_displace(&overflowing));

        // The drainer's pre-overflow sequence: reserve, then enqueue.
        assert!(scheduler.try_reserve(Instant::now(), 0, Duration::ZERO, &cooldown, &obs));
        assert!(
            !scheduler.would_displace(&overflowing),
            "a successful reservation frees the slot"
        );
        scheduler.enqueue(overflowing, &obs);

        assert_eq!(scheduler.pending_len(), FIRST_AUDIT_PENDING_CAP);
        assert_eq!(
            obs.capacity_evicted.load(Ordering::Relaxed),
            0,
            "no destructive eviction when a launch opportunity existed"
        );
    }

    /// Displacement stamps no suppression state: a displaced peer's next
    /// nomination re-enters like any newcomer (it is NOT window-deduped or
    /// treated as a duplicate), so under overload every peer keeps an
    /// unpredictable chance of prompt first audit.
    #[test]
    fn first_audit_displaced_peer_may_be_renominated() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mut scheduler = FirstAuditScheduler::new(Instant::now(), test_peer(99));
        let total = FIRST_AUDIT_PENDING_CAP + 1;

        for i in 0..total {
            let b = u8::try_from(i + 1).expect("test peer count fits u8");
            scheduler.enqueue(live_nomination(b), &obs);
        }
        assert_eq!(obs.capacity_evicted.load(Ordering::Relaxed), 1);
        // Find whichever peer the random displacement removed.
        let displaced = (1..=total)
            .map(|i| u8::try_from(i).expect("test peer count fits u8"))
            .find(|b| scheduler.pending.peek(&test_peer(*b)).is_none())
            .expect("exactly one admitted peer was displaced");

        scheduler.enqueue(live_nomination(displaced), &obs);

        assert!(
            scheduler.pending.peek(&test_peer(displaced)).is_some(),
            "the displaced peer re-enters the sample"
        );
        assert_eq!(scheduler.pending_len(), FIRST_AUDIT_PENDING_CAP);
        assert_eq!(obs.capacity_evicted.load(Ordering::Relaxed), 2);
        assert_eq!(obs.duplicates.load(Ordering::Relaxed), 0);
        assert_eq!(obs.window_deduped.load(Ordering::Relaxed), 0);
    }

    /// The periodic sweep collects expired pending entries even when the token
    /// bucket is empty — the reserve path returns at the budget gate and never
    /// scans — keeping the capped pending queue and the pending/oldest-age telemetry
    /// honest under fleet-wide starvation.
    #[test]
    fn first_audit_sweep_expired_collects_dead_entries_without_tokens() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mono = Instant::now();
        let mut scheduler = FirstAuditScheduler::new(mono, test_peer(99));

        let dead_quote = SystemTime::now()
            .checked_sub(GOSSIP_ANSWERABILITY_TTL)
            .and_then(|t| t.checked_sub(Duration::from_secs(60)))
            .expect("past wall time");
        scheduler.enqueue(
            MonetizedPinEvent {
                peer: test_peer(1),
                pin: [1; 32],
                key_count: 100,
                quote_ts: dead_quote,
            },
            &obs,
        );
        scheduler.enqueue(
            MonetizedPinEvent {
                peer: test_peer(2),
                pin: [2; 32],
                key_count: 100,
                quote_ts: SystemTime::now(),
            },
            &obs,
        );
        assert_eq!(scheduler.pending_len(), 2);

        // Empty the bucket so the reserve path is budget-gated (fleet-wide
        // starvation) and cannot collect the dead entry itself.
        scheduler.limiter.tokens = 0;
        let cooldown: HashMap<PeerId, Instant> = HashMap::new();
        assert!(!scheduler.try_reserve(mono, 0, Duration::ZERO, &cooldown, &obs));
        assert_eq!(
            scheduler.pending_len(),
            2,
            "budget-gated reserve scans nothing"
        );

        let wall_now = SystemTime::now();
        assert_eq!(scheduler.sweep_expired(wall_now, &obs), 1);
        assert_eq!(scheduler.pending_len(), 1);
        assert!(
            scheduler.pending.peek(&test_peer(2)).is_some(),
            "the live entry survives the sweep"
        );
        assert_eq!(obs.outside_answerability_window.load(Ordering::Relaxed), 1);
        let age_ms = scheduler.oldest_pending_quote_age_ms(wall_now);
        assert!(
            Duration::from_millis(age_ms) < GOSSIP_ANSWERABILITY_TTL,
            "the age gauge reflects only live work after the sweep"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn first_audit_answerability_cancel_is_state_neutral_and_retains_successor() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mono = Instant::now();
        let mut scheduler = FirstAuditScheduler::new(mono, test_peer(99));

        // A pre-existing window sentinel for an UNRELATED peer must survive the
        // cancel byte-for-byte (cancel never touches `recent`).
        let sentinel_peer = test_peer(0xAA);
        scheduler.limiter.promote(sentinel_peer, 500, mono);
        let sentinel_before = scheduler
            .limiter
            .recent
            .peek(&sentinel_peer)
            .copied()
            .expect("sentinel present");

        let peer = test_peer(1);
        let a = MonetizedPinEvent {
            peer,
            pin: [1; 32],
            key_count: 100,
            quote_ts: SystemTime::now(), // fresh: passes the horizon prefilter now
        };
        scheduler.enqueue(a, &obs);

        let tokens_before = scheduler.tokens();
        let lane_before = scheduler.oldest_first_lane;
        let launched_before = obs.launched.load(Ordering::Relaxed);
        let mut cooldown: HashMap<PeerId, Instant> = HashMap::new();

        // Reserve A (jitter 0 so it is immediately due).
        let inflight0 = obs.inflight.load(Ordering::Relaxed);
        assert!(scheduler.try_reserve(mono, inflight0, Duration::ZERO, &cooldown, &obs));
        assert_eq!(scheduler.reserved_peer(), Some(peer));
        assert_eq!(
            scheduler.tokens(),
            tokens_before - 1,
            "reserve consumes a token"
        );
        assert_eq!(
            obs.inflight.load(Ordering::Relaxed),
            1,
            "reserve holds a slot"
        );

        // A same-peer, same-count successor arrives DURING the reservation. It
        // must be retained (bypasses the window for the reserved peer) and must
        // NOT create a second reservation.
        let b = MonetizedPinEvent {
            peer,
            pin: [2; 32],
            key_count: 100,
            quote_ts: SystemTime::now(),
        };
        scheduler.enqueue(b, &obs);
        assert_eq!(scheduler.pending_len(), 1, "successor retained in pending");
        assert!(
            !scheduler.try_reserve(
                mono,
                obs.inflight.load(Ordering::Relaxed),
                Duration::ZERO,
                &cooldown,
                &obs
            ),
            "no second reservation while one is outstanding"
        );

        // Resolve A with an injected wall time PAST A's answerability cutoff.
        let reservation = scheduler
            .take_due_reservation(mono)
            .expect("A is due at jitter 0");
        let wall_fail = a
            .quote_ts
            .checked_add(GOSSIP_ANSWERABILITY_TTL)
            .and_then(|t| t.checked_add(Duration::from_secs(1)))
            .expect("past-cutoff wall time");
        let promoted = scheduler.resolve(reservation, wall_fail, mono, &mut cooldown, &obs);
        assert!(
            promoted.is_none(),
            "answerability lapsed -> cancelled, not promoted"
        );

        // State-neutral cancel.
        assert!(scheduler.first_audited.is_empty(), "no pin marked audited");
        assert!(
            scheduler.limiter.recent.peek(&peer).is_none(),
            "cancel stamps no per-peer window"
        );
        assert_eq!(
            scheduler.limiter.recent.peek(&sentinel_peer).copied(),
            Some(sentinel_before),
            "unrelated window sentinel untouched"
        );
        assert!(!cooldown.contains_key(&peer), "cancel stamps no cooldown");
        assert_eq!(
            scheduler.tokens(),
            tokens_before,
            "token refunded on cancel"
        );
        assert_eq!(
            obs.inflight.load(Ordering::Relaxed),
            0,
            "in-flight slot released"
        );
        assert_eq!(scheduler.oldest_first_lane, lane_before, "lane not flipped");
        assert_eq!(
            obs.launched.load(Ordering::Relaxed),
            launched_before,
            "no launch counted"
        );
        assert_eq!(
            obs.outside_answerability_window.load(Ordering::Relaxed),
            1,
            "the cancel reason is recorded"
        );

        // The successor is still pending and is now fully schedulable: a fresh
        // reserve makes B the next reservation (proving eligibility, not merely
        // that the limiter would admit it).
        assert_eq!(
            scheduler.pending_len(),
            1,
            "successor still pending after cancel"
        );
        assert!(scheduler.reserved.is_none());
        assert!(scheduler.try_reserve(
            mono,
            obs.inflight.load(Ordering::Relaxed),
            Duration::ZERO,
            &cooldown,
            &obs
        ));
        assert_eq!(
            scheduler.reserved_peer(),
            Some(peer),
            "the retained successor becomes the next reservation"
        );
    }

    /// ADR-0004 Amendment 2 (E'): when a promotion loses the shared-cooldown
    /// race, the reserved event is requeued ONLY if no same-peer successor is
    /// already pending. A successor arrived after the reservation, so it is the
    /// newer nomination (e.g. a count jump) and must not be overwritten by the
    /// older reserved event.
    #[test]
    fn first_audit_cooldown_race_requeue_preserves_newer_successor() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mono = Instant::now();
        let mut scheduler = FirstAuditScheduler::new(mono, test_peer(99));
        let peer = test_peer(1);

        // Reserve A.
        let a = MonetizedPinEvent {
            peer,
            pin: [1; 32],
            key_count: 100,
            quote_ts: SystemTime::now(),
        };
        scheduler.enqueue(a, &obs);
        let cooldown_reserve: HashMap<PeerId, Instant> = HashMap::new();
        assert!(scheduler.try_reserve(mono, 0, Duration::ZERO, &cooldown_reserve, &obs));

        // A newer same-peer successor B (a count jump) arrives during the
        // reservation and is retained.
        let b = MonetizedPinEvent {
            peer,
            pin: [2; 32],
            key_count: 400,
            quote_ts: SystemTime::now(),
        };
        scheduler.enqueue(b, &obs);
        assert_eq!(scheduler.pending_len(), 1);

        // Resolve A: answerability PASSES (fresh quote) but the shared cooldown
        // is already stamped for the peer, so promotion loses the race.
        let reservation = scheduler.take_due_reservation(mono).expect("due");
        let mut cooldown: HashMap<PeerId, Instant> = HashMap::new();
        cooldown.insert(peer, mono); // freshly on cooldown
        let promoted = scheduler.resolve(reservation, SystemTime::now(), mono, &mut cooldown, &obs);
        assert!(promoted.is_none(), "cooldown race -> not promoted");

        // B (newer) is preserved; A did NOT overwrite it.
        assert_eq!(scheduler.pending_len(), 1, "still exactly one pending");
        assert_eq!(
            scheduler.pending.peek(&peer).map(|e| e.pin),
            Some([2; 32]),
            "the newer successor B is retained, not the older reserved A"
        );
        assert!(scheduler.first_audited.is_empty());
        assert!(scheduler.limiter.recent.peek(&peer).is_none());
    }

    /// The oldest-pending-quote-age gauge reports the age of the OLDEST quote
    /// still awaiting a first audit (not the newest), is `0` on an empty queue,
    /// and saturates to `0` for a future-dated quote (clock skew) without
    /// panicking. A climbing value is the pending-work-aging-out signal.
    #[test]
    fn first_audit_oldest_pending_quote_age_tracks_the_oldest() {
        let now = SystemTime::now();
        let mut scheduler = FirstAuditScheduler::new(Instant::now(), test_peer(99));
        assert_eq!(
            scheduler.oldest_pending_quote_age_ms(now),
            0,
            "empty pending -> zero"
        );

        // Two peers: quotes 10s and 2s old. The gauge must track the older.
        for (peer_id, pin, secs) in [(1u8, [1; 32], 10u64), (2, [2; 32], 2)] {
            let _ = coalesce_first_audit_event(
                &mut scheduler.pending,
                MonetizedPinEvent {
                    peer: test_peer(peer_id),
                    pin,
                    key_count: 100,
                    quote_ts: now - Duration::from_secs(secs),
                },
                true,
                &mut scheduler.rng,
            );
        }
        assert_eq!(
            scheduler.oldest_pending_quote_age_ms(now),
            10_000,
            "tracks the oldest (10s), not the newest (2s)"
        );

        // A future-dated quote (clock skew) saturates to zero, never panics.
        let mut skewed = FirstAuditScheduler::new(Instant::now(), test_peer(99));
        let _ = coalesce_first_audit_event(
            &mut skewed.pending,
            MonetizedPinEvent {
                peer: test_peer(3),
                pin: [3; 32],
                key_count: 100,
                quote_ts: now + Duration::from_secs(5),
            },
            true,
            &mut skewed.rng,
        );
        assert_eq!(
            skewed.oldest_pending_quote_age_ms(now),
            0,
            "future quote_ts saturates to zero"
        );
    }

    /// A flood of strictly-lower-count same-peer nominations must neither
    /// displace the retained higher pin NOR disturb its recency position (each
    /// is suppressed via `peek`, no `push`), and each must be counted as
    /// `suppressed_lower` — the attempted cheaper-pin self-erasure signal.
    /// Recency is asserted DIRECTLY via the queue's MRU-to-LRU iteration order
    /// (the documented `lru` contract that also drives the reserve scan's lane
    /// ordering), deliberately independent of the overflow policy: eviction is
    /// random-victim, so no assertion may require a particular peer to be
    /// displaced.
    #[test]
    fn first_audit_suppressed_lower_flood_leaves_recency_and_counts() {
        let mut pending: LruCache<PeerId, MonetizedPinEvent> =
            LruCache::new(NonZeroUsize::new(2).unwrap());
        let mut rng = StdRng::seed_from_u64(11);
        let victim = test_peer(1);
        let other = test_peer(2);
        // Victim (high count) inserted first (older), then `other` (newer/MRU).
        let _ = coalesce_first_audit_event(
            &mut pending,
            MonetizedPinEvent {
                peer: victim,
                pin: [1; 32],
                key_count: 400,
                quote_ts: SystemTime::now(),
            },
            true,
            &mut rng,
        );
        let _ = coalesce_first_audit_event(
            &mut pending,
            MonetizedPinEvent {
                peer: other,
                pin: [9; 32],
                key_count: 100,
                quote_ts: SystemTime::now(),
            },
            true,
            &mut rng,
        );
        let order_before: Vec<PeerId> = pending.iter().map(|(p, _)| *p).collect();
        assert_eq!(
            order_before,
            vec![other, victim],
            "sanity: `other` is MRU, the victim is LRU"
        );

        // Flood the victim with cheaper nominations.
        let mut suppressed = 0u64;
        for i in 0..8u8 {
            let out = coalesce_first_audit_event(
                &mut pending,
                MonetizedPinEvent {
                    peer: victim,
                    pin: [i; 32],
                    key_count: 50,
                    quote_ts: SystemTime::now(),
                },
                true,
                &mut rng,
            );
            assert_eq!(out, FirstAuditQueueOutcome::SuppressedLower);
            suppressed += 1;
        }
        assert_eq!(suppressed, 8);
        // Victim pin/count unchanged.
        assert_eq!(
            pending.peek(&victim).map(|e| (e.pin, e.key_count)),
            Some(([1; 32], 400))
        );
        // Recency untouched: the iteration order (which the reserve lanes
        // consume) is byte-for-byte what it was before the flood.
        let order_after: Vec<PeerId> = pending.iter().map(|(p, _)| *p).collect();
        assert_eq!(
            order_after, order_before,
            "the suppressed-lower flood must not have changed any recency position"
        );
    }

    /// The cooldown-race requeue counts a genuine different-peer capacity
    /// eviction (the ADR promises capacity loss is observable).
    #[test]
    fn first_audit_cooldown_race_requeue_counts_capacity_eviction() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mono = Instant::now();
        let mut scheduler = FirstAuditScheduler::new(mono, test_peer(99));
        // Pending capacity 1 so a requeue of a different peer must evict.
        scheduler.pending = LruCache::new(NonZeroUsize::new(1).unwrap());
        let reserved_peer = test_peer(1);
        let other_peer = test_peer(2);

        // Reserve peer 1.
        scheduler.enqueue(
            MonetizedPinEvent {
                peer: reserved_peer,
                pin: [1; 32],
                key_count: 100,
                quote_ts: SystemTime::now(),
            },
            &obs,
        );
        let cooldown_read: HashMap<PeerId, Instant> = HashMap::new();
        assert!(scheduler.try_reserve(mono, 0, Duration::ZERO, &cooldown_read, &obs));

        // A DIFFERENT peer fills the single pending slot during the reservation.
        scheduler.enqueue(
            MonetizedPinEvent {
                peer: other_peer,
                pin: [2; 32],
                key_count: 100,
                quote_ts: SystemTime::now(),
            },
            &obs,
        );
        assert_eq!(scheduler.pending_len(), 1);

        // Resolve peer 1: cooldown race -> requeue peer 1, evicting peer 2.
        let reservation = scheduler.take_due_reservation(mono).expect("due");
        let mut cooldown: HashMap<PeerId, Instant> = HashMap::new();
        cooldown.insert(reserved_peer, mono);
        let cap_before = obs.capacity_evicted.load(Ordering::Relaxed);
        assert!(scheduler
            .resolve(reservation, SystemTime::now(), mono, &mut cooldown, &obs)
            .is_none());
        assert_eq!(
            obs.capacity_evicted.load(Ordering::Relaxed),
            cap_before + 1,
            "the requeue eviction of a different peer is counted"
        );
        assert_eq!(
            scheduler.pending.peek(&reserved_peer).map(|e| e.pin),
            Some([1; 32])
        );
    }

    /// ADR-0004 Amendment 2 (reviewer blocker): a strictly-lower-count same-peer
    /// nomination arriving while an inflated pin is PENDING must not displace it.
    /// The inflated pin stays and is the one launched.
    #[test]
    fn first_audit_pending_lower_count_does_not_replace_higher() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mono = Instant::now();
        let mut scheduler = FirstAuditScheduler::new(mono, test_peer(99));
        let peer = test_peer(1);

        // Inflated (high-count) sidecar pin lands in pending.
        scheduler.enqueue(
            MonetizedPinEvent {
                peer,
                pin: [1; 32],
                key_count: 400,
                quote_ts: SystemTime::now(),
            },
            &obs,
        );
        // A cheaper same-peer settlement arrives right after.
        scheduler.enqueue(
            MonetizedPinEvent {
                peer,
                pin: [2; 32],
                key_count: 100,
                quote_ts: SystemTime::now(),
            },
            &obs,
        );

        assert_eq!(scheduler.pending_len(), 1);
        assert_eq!(
            scheduler.pending.peek(&peer).map(|e| (e.pin, e.key_count)),
            Some(([1; 32], 400)),
            "the inflated pin must not be erased by the cheaper successor"
        );
        // The dropped cheaper nomination is counted through the enqueue path.
        assert_eq!(
            obs.suppressed_lower.load(Ordering::Relaxed),
            1,
            "the attempted cheaper-pin self-erasure is observable"
        );

        // It reserves and promotes as the inflated pin/count.
        let cooldown_read: HashMap<PeerId, Instant> = HashMap::new();
        assert!(scheduler.try_reserve(mono, 0, Duration::ZERO, &cooldown_read, &obs));
        let reservation = scheduler.take_due_reservation(mono).expect("due");
        let mut cooldown: HashMap<PeerId, Instant> = HashMap::new();
        let (event, _slot) = scheduler
            .resolve(reservation, SystemTime::now(), mono, &mut cooldown, &obs)
            .expect("promotes");
        assert_eq!((event.pin, event.key_count), ([1; 32], 400));
    }

    /// ADR-0004 Amendment 2 (reviewer blocker): a RESERVED inflated pin that
    /// loses the cooldown race must be requeued OVER a lower-count same-peer
    /// successor that arrived during its jitter, and must remain launchable once
    /// the shared cooldown expires — the cheaper successor cannot suppress it.
    #[test]
    fn first_audit_cooldown_race_requeues_reserved_higher_over_lower_successor() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mono = Instant::now();
        let mut scheduler = FirstAuditScheduler::new(mono, test_peer(99));
        let peer = test_peer(1);

        // Reserve the inflated pin.
        scheduler.enqueue(
            MonetizedPinEvent {
                peer,
                pin: [1; 32],
                key_count: 400,
                quote_ts: SystemTime::now(),
            },
            &obs,
        );
        let cooldown_read: HashMap<PeerId, Instant> = HashMap::new();
        assert!(scheduler.try_reserve(mono, 0, Duration::ZERO, &cooldown_read, &obs));

        // A cheaper successor arrives during the reservation (bypasses the
        // window as the reserved peer) and sits in pending.
        scheduler.enqueue(
            MonetizedPinEvent {
                peer,
                pin: [2; 32],
                key_count: 100,
                quote_ts: SystemTime::now(),
            },
            &obs,
        );
        assert_eq!(scheduler.pending_len(), 1);

        // Resolve: answerability passes but the shared cooldown is already
        // stamped, so the reservation loses the race and requeues.
        let reservation = scheduler.take_due_reservation(mono).expect("due");
        let mut cooldown: HashMap<PeerId, Instant> = HashMap::new();
        cooldown.insert(peer, mono);
        assert!(scheduler
            .resolve(reservation, SystemTime::now(), mono, &mut cooldown, &obs)
            .is_none());

        // The inflated pin (400) replaced the cheaper successor (100).
        assert_eq!(scheduler.pending_len(), 1);
        assert_eq!(
            scheduler.pending.peek(&peer).map(|e| (e.pin, e.key_count)),
            Some(([1; 32], 400)),
            "the inflated reserved pin must survive the requeue over the cheaper successor"
        );
        assert!(scheduler.first_audited.is_empty());
        assert!(scheduler.limiter.recent.peek(&peer).is_none());

        // Once the shared cooldown expires, the inflated pin reserves and
        // promotes with its intended pin/count.
        let later = mono
            .checked_add(Duration::from_secs(
                config::AUDIT_ON_GOSSIP_COOLDOWN_SECS + 1,
            ))
            .expect("later");
        let cooldown_read_later: HashMap<PeerId, Instant> = HashMap::new();
        assert!(scheduler.try_reserve(later, 0, Duration::ZERO, &cooldown_read_later, &obs));
        let reservation = scheduler.take_due_reservation(later).expect("due");
        let mut cooldown_later: HashMap<PeerId, Instant> = HashMap::new();
        let (event, _slot) = scheduler
            .resolve(
                reservation,
                SystemTime::now(),
                later,
                &mut cooldown_later,
                &obs,
            )
            .expect("promotes after cooldown");
        assert_eq!((event.pin, event.key_count), ([1; 32], 400));
    }

    /// ADR-0004 Amendment 2 (E'): consecutive PROMOTIONS strictly alternate the
    /// launch lane, driven through the real scheduler (reserve -> resolve ->
    /// promote), so a stream of fresh nominations cannot keep every launch on
    /// the newest lane and starve the oldest.
    #[test]
    fn first_audit_lane_alternates_across_promotions() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mono = Instant::now();
        let mut scheduler = FirstAuditScheduler::new(mono, test_peer(99));
        let mut cooldown: HashMap<PeerId, Instant> = HashMap::new();

        // Two distinct peers; the newest-inserted is the MRU (newest lane end).
        let oldest_peer = test_peer(1);
        let newest_peer = test_peer(2);
        scheduler.enqueue(
            MonetizedPinEvent {
                peer: oldest_peer,
                pin: [1; 32],
                key_count: 100,
                quote_ts: SystemTime::now(),
            },
            &obs,
        );
        scheduler.enqueue(
            MonetizedPinEvent {
                peer: newest_peer,
                pin: [2; 32],
                key_count: 100,
                quote_ts: SystemTime::now(),
            },
            &obs,
        );

        let mut launched_peers = Vec::new();
        for _ in 0..2 {
            assert!(scheduler.try_reserve(
                mono,
                obs.inflight.load(Ordering::Relaxed),
                Duration::ZERO,
                &cooldown,
                &obs
            ));
            let reservation = scheduler.take_due_reservation(mono).expect("due");
            // Answerable wall time == the quote's own time (age 0).
            let (event, _slot) = scheduler
                .resolve(reservation, SystemTime::now(), mono, &mut cooldown, &obs)
                .expect("fresh in-window quote promotes");
            launched_peers.push(event.peer);
        }

        // First launch takes the newest lane (lane starts false = newest), the
        // second takes the oldest lane: strict alternation.
        assert_eq!(
            launched_peers,
            vec![newest_peer, oldest_peer],
            "consecutive promotions alternate newest-then-oldest lane"
        );
    }

    #[test]
    fn first_audit_count_jump_boundaries() {
        // Exactly 1.5x is NOT a jump; strictly above is.
        assert!(!first_audit_count_jump(100, 150));
        assert!(first_audit_count_jump(100, 151));
        // Anything beats an audited zero; zero never jumps.
        assert!(first_audit_count_jump(0, 1));
        assert!(!first_audit_count_jump(0, 0));
        // Equal max counts must not jump (and must not overflow).
        assert!(!first_audit_count_jump(u32::MAX, u32::MAX));
    }

    /// A verified payment's quote list includes the local node's own quote, so
    /// the verifier emits a monetized-pin event for the local peer on every
    /// payment it verifies. The node cannot network-audit itself, so the
    /// scheduler must drop such an event at ingress: never queued, and hence
    /// never launched nor marked first-audited.
    #[test]
    fn first_audit_queue_drops_self_targeting_events() {
        let obs = Arc::new(FirstAuditObservability::default());
        let self_peer = test_peer(1);
        let mut scheduler = FirstAuditScheduler::new(Instant::now(), self_peer);
        let self_event = MonetizedPinEvent {
            peer: self_peer,
            pin: [7; 32],
            key_count: 1,
            quote_ts: SystemTime::now(),
        };

        scheduler.enqueue(self_event, &obs);
        assert_eq!(obs.self_target_skipped.load(Ordering::Relaxed), 1);
        assert_eq!(obs.queued.load(Ordering::Relaxed), 0);
        assert_eq!(scheduler.pending_len(), 0, "self-target must never queue");

        // A remote peer's event still queues normally under the same filter.
        let remote_event = MonetizedPinEvent {
            peer: test_peer(2),
            pin: [8; 32],
            ..self_event
        };
        scheduler.enqueue(remote_event, &obs);
        assert_eq!(obs.queued.load(Ordering::Relaxed), 1);
        assert_eq!(scheduler.pending_len(), 1);
        assert_eq!(
            obs.self_target_skipped.load(Ordering::Relaxed),
            1,
            "remote event must not count as a self-target skip"
        );
    }

    #[test]
    fn fresh_offer_runs_store_admission_payment_checks() {
        let context = fresh_offer_payment_context();
        assert_eq!(context, VerificationContext::FreshReplication);
        // Fresh replication must keep verifying exactly like a direct client
        // PUT (store-strength cache, same live checks); the variant only
        // exists so price-floor telemetry can tell the two paths apart.
        assert!(context.is_store_admission());
    }

    #[test]
    fn paid_notify_uses_paid_list_admission_payment_checks() {
        assert_eq!(
            paid_notify_payment_context(),
            VerificationContext::PaidListAdmission
        );
    }

    /// ADR-0004 A1 (guardrail A): the monetized first-audit only fires for a
    /// signed quote inside the answerability window, fail-closed on BOTH ends so a
    /// stale or future/skewed client-forwarded quote cannot frame an honest node.
    #[test]
    fn monetized_quote_audit_window_fails_closed_both_ends() {
        let now = SystemTime::now();
        // Fresh (just quoted) and small future/past skew -> audited.
        assert!(quote_within_audit_window(now, now));
        assert!(quote_within_audit_window(
            now + Duration::from_secs(60),
            now
        ));
        assert!(quote_within_audit_window(
            now - Duration::from_secs(3600),
            now
        ));
        // Far future (badly-skewed / replayed) -> skipped.
        assert!(!quote_within_audit_window(
            now + MONETIZED_AUDIT_SKEW_MARGIN + Duration::from_secs(60),
            now
        ));
        // Older than the window -> skipped (pin may have aged out).
        assert!(!quote_within_audit_window(
            now - GOSSIP_ANSWERABILITY_TTL,
            now
        ));
    }

    #[test]
    fn audit_timeout_preserves_active_bootstrap_claim() {
        assert!(!audit_failure_clears_bootstrap_claim(
            &AuditFailureReason::Timeout
        ));
    }

    fn strike_peer(b: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = b;
        PeerId::from_bytes(bytes)
    }

    // ADR-0002: "occasional surprise exams, keeps load low" — the per-peer
    // cooldown must collapse a gossip flood into at most one audit per window.

    #[test]
    fn gossip_flood_yields_at_most_one_audit_per_cooldown_window() {
        let peer = strike_peer(1);
        let mut map: HashMap<PeerId, Instant> = HashMap::new();
        let t0 = Instant::now();
        // First gossip in the window passes; a burst of further gossips at the
        // same instant are all suppressed.
        assert!(cooldown_allows_audit(&mut map, &peer, t0));
        let mut passed = 1;
        for _ in 0..100 {
            if cooldown_allows_audit(&mut map, &peer, t0) {
                passed += 1;
            }
        }
        assert_eq!(
            passed, 1,
            "a flood at one instant must trigger exactly one audit"
        );
    }

    // ADR-0002 ordering invariant: `maybe_trigger_gossip_audit` stamps the
    // per-peer cooldown BEFORE the probability lottery, so a LOSING ticket still
    // consumes the window. This is the property the isolated cooldown tests above
    // cannot see: they never sample the lottery, so a regression that reordered
    // the gates (sample probability first, only stamp the cooldown on a win)
    // would still pass them while breaking flood-resistance: a flood would then
    // re-roll the lottery on EVERY message until one won, multiplying audits.
    //
    // We model the exact production gate order (attempt-window, lottery,
    // shared cooldown) with a lottery driven by a fixed outcome instead of
    // `gen_bool(..)`. The first message LOSES the lottery; the remaining flood
    // messages all WIN. With the production order, the losing first ticket
    // burns the ATTEMPT window and every later winner in the same window is
    // blocked, so there are 0 audits this window. If the gates were flipped,
    // the second message's winning ticket would slip through. The window only
    // reopens after it elapses.
    //
    // FLIPS IF: the lottery is sampled before the attempt-window
    // check-and-stamp (a losing ticket no longer consumes the window),
    // re-enabling a flood-amplified audit storm.
    #[test]
    fn losing_lottery_still_consumes_attempt_window() {
        // Calls the SHIPPED `audit_launch_decision` (the same function
        // `maybe_trigger_gossip_audit` uses), so a reorder of the gates in
        // production fails this test — not a local reimplementation.
        let peer = strike_peer(3);
        let mut attempts: HashMap<PeerId, Instant> = HashMap::new();
        let mut launched: HashMap<PeerId, Instant> = HashMap::new();
        let t0 = Instant::now();

        // First flooded message at t0 LOSES the lottery, but the attempt window
        // is stamped BEFORE the lottery is consulted, so the window is consumed.
        assert!(
            !audit_launch_decision(&mut attempts, &mut launched, &peer, t0, false),
            "a losing ticket launches no audit"
        );

        // 99 more flooded messages at the same instant would all WIN the lottery,
        // yet every one must be blocked by the attempt window the loser stamped.
        // (If production sampled the lottery FIRST, these would each get a fresh
        // roll and audits would multiply — this assertion catches that reorder.)
        let mut audits = 0;
        for _ in 0..99 {
            if audit_launch_decision(&mut attempts, &mut launched, &peer, t0, true) {
                audits += 1;
            }
        }
        assert_eq!(
            audits, 0,
            "a losing first ticket must consume the attempt window so no later \
             flooded message in the same window can audit"
        );

        // The window only reopens after it elapses; the next winning ticket
        // then launches exactly one audit and stamps the SHARED cooldown.
        let after = t0 + Duration::from_secs(config::AUDIT_ON_GOSSIP_COOLDOWN_SECS + 1);
        assert!(
            audit_launch_decision(&mut attempts, &mut launched, &peer, after, true),
            "after the window a winning ticket audits again"
        );
        assert!(
            launched.contains_key(&peer),
            "a real launch stamps the shared cooldown"
        );
    }

    /// The reviewer-flagged suppression route: a LOSING gossip lottery must not
    /// stamp the SHARED audit cooldown, otherwise repeated losses (one per
    /// 30-minute window, no challenge ever sent) keep a paid monetized pin's
    /// first audit deferred until its answerability window expires.
    ///
    /// FLIPS IF: `audit_launch_decision` stamps the shared `launched` map on a
    /// loss (the pre-split behavior, where both paths shared one map).
    #[test]
    fn losing_lottery_does_not_suppress_monetized_first_audit() {
        let peer = strike_peer(4);
        let mut attempts: HashMap<PeerId, Instant> = HashMap::new();
        let mut launched: HashMap<PeerId, Instant> = HashMap::new();
        let t0 = Instant::now();

        // A losing ticket consumes the gossip attempt window...
        assert!(!audit_launch_decision(
            &mut attempts,
            &mut launched,
            &peer,
            t0,
            false
        ));
        // ...but leaves the shared map untouched, so the first-audit reserve
        // gate (read-only) and the authoritative promotion check-and-stamp both
        // still allow the paid audit to launch immediately.
        assert!(
            cooldown_would_allow(&launched, &peer, t0),
            "reserve gate must not see a losing ticket as audit coverage"
        );
        assert!(
            cooldown_allows_audit(&mut launched, &peer, t0),
            "promotion must not be deferred by a losing ticket"
        );

        // Conversely a WINNING ticket (real audit sent) does suppress the
        // first audit for the window, which is the intended shared semantics.
        let peer_won = strike_peer(5);
        assert!(audit_launch_decision(
            &mut attempts,
            &mut launched,
            &peer_won,
            t0,
            true
        ));
        assert!(
            !cooldown_would_allow(&launched, &peer_won, t0),
            "a real gossip audit still covers the peer for the window"
        );
    }

    #[test]
    fn cooldown_lets_audit_through_after_the_window() {
        let peer = strike_peer(2);
        let mut map: HashMap<PeerId, Instant> = HashMap::new();
        let t0 = Instant::now();
        assert!(cooldown_allows_audit(&mut map, &peer, t0));
        // Within the window: suppressed.
        let within = t0 + Duration::from_secs(config::AUDIT_ON_GOSSIP_COOLDOWN_SECS - 1);
        assert!(!cooldown_allows_audit(&mut map, &peer, within));
        // Past the window: allowed again.
        let after = t0 + Duration::from_secs(config::AUDIT_ON_GOSSIP_COOLDOWN_SECS + 1);
        assert!(cooldown_allows_audit(&mut map, &peer, after));
    }

    #[test]
    fn cooldown_is_per_peer_independent() {
        let mut map: HashMap<PeerId, Instant> = HashMap::new();
        let t0 = Instant::now();
        // Different peers each get their own first-audit pass at the same instant.
        for i in 0..20u8 {
            assert!(
                cooldown_allows_audit(&mut map, &strike_peer(i), t0),
                "peer {i} should be auditable independently"
            );
        }
    }

    #[test]
    fn audit_on_gossip_constants_match_adr() {
        // Tripwire on the ADR-locked tunables. The spot-check count sits at the
        // top of the auditor's 3..=5 band (the auditor clamps to that band, so
        // values above 5 would silently never be requested).
        assert_eq!(config::AUDIT_SPOTCHECK_COUNT, 5);
        assert!((config::AUDIT_ON_GOSSIP_PROBABILITY - 0.2).abs() < f64::EPSILON);
        assert_eq!(config::AUDIT_ON_GOSSIP_COOLDOWN_SECS, 30 * 60);
    }

    // (d) A confirmed storage-integrity failure penalizes immediately and
    // revokes credit; it is not a timeout.
    #[test]
    fn digest_mismatch_is_not_a_timeout_and_penalizes_immediately() {
        assert!(audit_failure_clears_bootstrap_claim(
            &AuditFailureReason::DigestMismatch
        ));
        assert!(audit_failure_revokes_holder_credit(
            &AuditFailureReason::DigestMismatch
        ));
    }

    /// The exact decision the `Failed` arm of `handle_subtree_audit_result`
    /// uses: confirmed failures revoke credit, `Timeout` does not.
    #[test]
    fn confirmed_failures_revoke_credit_timeout_does_not() {
        for reason in [
            AuditFailureReason::MalformedResponse,
            AuditFailureReason::DigestMismatch,
            AuditFailureReason::KeyAbsent,
            AuditFailureReason::Rejected,
        ] {
            assert!(
                audit_failure_revokes_holder_credit(&reason),
                "confirmed failure {reason:?} must revoke holder credit"
            );
        }
        assert!(
            !audit_failure_revokes_holder_credit(&AuditFailureReason::Timeout),
            "Timeout must NOT revoke credit (single dropped packet != storage loss)"
        );
    }

    /// Wiring test for the security fix: the helper the handler calls
    /// actually strips a credited peer on a confirmed failure
    /// (`DigestMismatch`), and actually RETAINS credit on `Timeout`.
    /// Records genuine credit first so neither assertion is vacuous;
    /// this fails if `forget_peer` stops being called, or if the
    /// `Timeout` exclusion is dropped (both verified by mutation).
    #[test]
    fn apply_revocation_strips_on_digest_mismatch_retains_on_timeout() {
        let peer = test_peer(0xAB);
        let key = test_key(1);
        let hash = [0xCD; 32];

        // Confirmed failure -> credit revoked.
        let mut provers = RecentProvers::new();
        provers.record_proof(key, peer, hash, Instant::now());
        assert!(
            provers.is_credited_holder(&key, &peer, &hash),
            "precondition: peer credited before failure"
        );
        apply_audit_failure_credit_revocation(
            &mut provers,
            &peer,
            &AuditFailureReason::DigestMismatch,
        );
        assert!(
            !provers.is_credited_holder(&key, &peer, &hash),
            "DigestMismatch must strip the peer's holder credit"
        );

        // Timeout -> credit retained.
        let mut provers_timeout = RecentProvers::new();
        provers_timeout.record_proof(key, peer, hash, Instant::now());
        apply_audit_failure_credit_revocation(
            &mut provers_timeout,
            &peer,
            &AuditFailureReason::Timeout,
        );
        assert!(
            provers_timeout.is_credited_holder(&key, &peer, &hash),
            "Timeout must retain holder credit (deliberate liveness cushion)"
        );
    }

    #[test]
    fn decoded_audit_failures_clear_active_bootstrap_claim() {
        for reason in [
            AuditFailureReason::MalformedResponse,
            AuditFailureReason::DigestMismatch,
            AuditFailureReason::KeyAbsent,
            AuditFailureReason::Rejected,
        ] {
            assert!(
                audit_failure_clears_bootstrap_claim(&reason),
                "decoded non-bootstrap failure {reason:?} should clear active claim"
            );
        }
    }

    #[test]
    fn first_failed_key_label_truncates_to_16_hex_chars() {
        // The high-order 8 bytes of the XorName determine the label so an
        // operator can group audit-failures on the same chunk prefix.
        let mut key = [0u8; 32];
        key[0] = 0x18;
        key[7] = 0xff;
        // Low-order bytes (positions 8..32) are deliberately set to 0xAA
        // to verify they are NOT included in the label.
        for byte in &mut key[8..] {
            *byte = 0xAA;
        }
        let label = first_failed_key_label(&[key]);
        // Only the first 8 bytes are encoded, low-order bytes are dropped.
        assert_eq!(label, "0x18000000000000ff");
        assert_eq!(label.len(), "0x".len() + 16);
    }

    #[test]
    fn first_failed_key_label_falls_back_when_empty() {
        // Should never happen in production (audit failure handling rejects
        // empty sets), but the formatter must still produce a valid label
        // so the log line doesn't contain a misleading default.
        assert_eq!(first_failed_key_label(&[]), "0x");
    }

    #[test]
    fn first_failed_key_label_uses_first_key_only() {
        let first = [0x11u8; 32];
        let second = [0x22u8; 32];
        assert_eq!(
            first_failed_key_label(&[first, second]),
            format!("0x{}", hex::encode(&first[..8]))
        );
    }
}
