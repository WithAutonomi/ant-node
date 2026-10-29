//! The fetch busy reply: what each side does when a responder cannot admit a
//! fetch.
//!
//! A responder that refuses a fetch at admission used to stay silent. The
//! requester then waited its whole fetch timeout, and saorsa-core charged the
//! responder a connection timeout it had not earned. A requester that says it
//! understands [`FetchResponse::Busy`] is now told at once instead.
//!
//! Two bounds keep the new reply from costing more than the silence it
//! replaces:
//!
//! - **Responder:** a busy reply is a send the node never made before, caused
//!   by a request it is refusing, and like every message it is signed, so it
//!   costs a signature and about 5 KiB on the wire. [`FetchBusyReplyLimiter`]
//!   caps those sends per peer and overall, and how many to one peer may be in
//!   flight at once.
//!   Past any cap a refusal is silent again, which is exactly what every
//!   refusal was before.
//! - **Requester:** a busy answer is not a reason to ask again at once.
//!   [`busy_wait`] keeps the attempt, and so its fetch slot, for a few seconds
//!   before the key moves on, so a requester asks at most once per wait per
//!   slot instead of as fast as answers come back. The attempt then ends as a
//!   source failure, exactly as the silent timeout did, minus the trust charge
//!   while the source is within its neutral allowance (see below).
//!   [`SourceBusyTracker`] also puts a busy source last when choosing where to
//!   start or retry a key, for longer each time it stays busy, so a requester
//!   does not keep picking a holder that just said it cannot take more.
//!
//! A busy answer costs no trust only while it can still be passing overload.
//! A source gets [`FETCH_BUSY_NEUTRAL_ALLOWANCE`] busy answers in a row, across
//! all keys, before it next serves this requester. Past that, until it serves
//! once, each busy answer is handled as the silent refusal it replaces: the
//! attempt holds its slot until its fetch timeout runs out (an answer later
//! than that adds no wait), and the source is then charged the same trust.
//! Without that bound a holder could keep the data, answer its storage audits
//! and say busy to every fetch for good, at no cost.
//!
//! [`FetchResponse::Busy`]: crate::replication::protocol::FetchResponse::Busy

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use saorsa_core::identity::PeerId;

use super::audit_metrics;

/// Shortest time a requester waits after a busy answer before moving on.
///
/// A responder refuses because its admitted fetches, each up to a 4 MiB chunk
/// sent over a home upload link, are still being served. A share frees in
/// seconds, not milliseconds, so asking again sooner would mostly be refused
/// again.
pub const FETCH_BUSY_WAIT_MIN: Duration = Duration::from_secs(5);

/// Longest time a requester waits after a busy answer before moving on.
///
/// Waits are spread uniformly between the two bounds, so requesters refused
/// together do not all come back together.
pub const FETCH_BUSY_WAIT_MAX: Duration = Duration::from_secs(10);

/// The jitter a requester adds to [`FETCH_BUSY_WAIT_MIN`]: drawn uniformly from
/// zero to this, inclusive.
pub const FETCH_BUSY_WAIT_SPREAD: Duration =
    FETCH_BUSY_WAIT_MAX.saturating_sub(FETCH_BUSY_WAIT_MIN);

/// Busy answers in a row that a source may give this requester, before it
/// next serves it, at no trust cost.
///
/// Honest overload passes: a share frees in seconds. A source that keeps
/// answering busy cannot be told apart from one that keeps the data and will
/// not serve it. So past this many, until the source serves this requester
/// once, each busy answer is handled as the silent refusal it replaces: the
/// attempt holds its slot until its fetch timeout, counted from when it
/// began, runs out (an answer later than that adds no wait), and the source
/// is then charged the same trust. Silence's
/// timeout starts once any dial is done, so after a cold dial the charge can
/// come up to that dial's time sooner. Only serving restores the allowance;
/// time does not.
///
/// The count lives in memory, so a restart of the requester starts every
/// source afresh: at most this many free busy answers per source per run.
///
/// With two answers a round, one for each request in a peer's reply burst,
/// eight is four rounds of being put last: minutes, when the requester has
/// other holders to ask, and well under a minute when it has none.
pub const FETCH_BUSY_NEUTRAL_ALLOWANCE: u32 = 8;

/// Longest a responder spends handing one busy reply to the transport.
///
/// A reply that cannot be handed over in this long is abandoned: the requester
/// then gets the silence it would have had anyway. Without it, a peer that is
/// slow to accept data could hold a send permit indefinitely.
pub const FETCH_BUSY_REPLY_SEND_TIMEOUT: Duration = Duration::from_secs(2);

/// Busy replies one peer may receive back to back, and the most to it that
/// may be in flight at once.
///
/// The same as the per-peer fetch admission share, so a requester that sent
/// one share too many at once hears about each refusal.
const PEER_BURST: u32 = 2;

/// Sustained rate of busy replies to one peer: one per this interval.
///
/// A requester that waits [`FETCH_BUSY_WAIT_MIN`] after each busy answer never
/// comes near it. A peer that ignores the answers and keeps sending gets one
/// reply a second, and silence for the rest.
const PEER_INTERVAL: Duration = Duration::from_secs(1);

/// Busy replies this node may send back to back across all peers.
///
/// Every message is signed, which adds about 5 KiB to the wire and a
/// signature's worth of CPU, so the global allowance is what bounds the cost.
/// Burst and rate together allow at most 48 replies, about 250 KiB, in any one
/// second, and 16 a second, about 85 KiB/s, sustained. The burst lets a node
/// that becomes full answer a whole pool's worth of peers at once.
const GLOBAL_BURST: u32 = 32;

/// Sustained rate of busy replies across all peers: one per this interval,
/// 16 a second.
const GLOBAL_INTERVAL: Duration = Duration::from_micros(62_500);

/// Most peers whose busy-reply allowance is tracked at once.
///
/// A peer whose allowance has fully refilled and has no reply in flight
/// carries no information and is dropped first. If every tracked peer is still
/// being limited, a new peer gets silence rather than an entry, so the table
/// cannot grow without bound.
const MAX_TRACKED_PEERS: usize = 4096;

/// Longest a source that keeps answering busy is put last.
const MAX_SOURCE_COOLDOWN: Duration = Duration::from_mins(1);

/// Busy answers after which a source's cooldown stops doubling: the wait,
/// then two, four and eight times it, capped at [`MAX_SOURCE_COOLDOWN`].
const MAX_COOLDOWN_DOUBLINGS: u32 = 3;

/// A source that has not answered busy for this long starts a new busy spell
/// with its next busy answer: its cooldown starts again from the wait, so one
/// busy spell is not held against its scheduling for good. What it owes
/// against its neutral allowance does not start again.
const BUSY_SPELL_GAP: Duration = Duration::from_mins(10);

/// Most sources whose busy record is kept at once.
///
/// Records go only when their source serves, so a full table forgets nothing
/// to make room. A source it does not already hold is then charged for every
/// busy answer, as for silence, and is not put last. A node fetches from its
/// neighbourhood, far fewer peers than this, and the table empties on restart.
const MAX_TRACKED_SOURCES: usize = 4096;

/// How long to wait after a busy answer, given `remaining`, the time left
/// before the attempt's fetch timeout would have expired.
///
/// The wait is [`FETCH_BUSY_WAIT_MIN`] plus `jitter`, which the caller draws
/// from `0..=FETCH_BUSY_WAIT_SPREAD` and which is clamped to that range. It
/// never outlasts `remaining`, so a busy answer never leaves a key waiting
/// longer than the silent refusal it replaces. (A fetch timeout shorter than
/// the minimum wait, which only tests configure, shortens the wait with it.)
#[must_use]
pub fn busy_wait(remaining: Duration, jitter: Duration) -> Duration {
    FETCH_BUSY_WAIT_MIN
        .saturating_add(jitter.min(FETCH_BUSY_WAIT_SPREAD))
        .min(remaining)
}

/// When an attempt answered busy at `now` lets go of its fetch slot, given
/// `wait`, the busy wait drawn for it, and `deadline`, when the attempt's fetch
/// timeout runs out.
///
/// Within the neutral allowance it is once the busy wait is over; past it, at
/// the deadline, as silence would have held it. Either way the returned wake
/// time is never after `deadline`, and one already past adds no wait: an answer
/// that arrives after the deadline releases the slot at once, so the slot is
/// held no longer than silence would have held it. A fixed time rather than a
/// length, so nothing between the answer and the sleep can stretch it.
#[must_use]
pub fn busy_wake(answer: BusyAnswer, wait: Duration, now: Instant, deadline: Instant) -> Instant {
    if answer.charged {
        deadline
    } else {
        now.checked_add(wait)
            .map_or(deadline, |done| done.min(deadline))
    }
}

/// A generic cell rate limiter: `burst` events back to back, then one per
/// `interval`.
///
/// It keeps only the theoretical arrival time of the next event, so it needs no
/// floating point and no refill timer.
#[derive(Debug, Default, Clone, Copy)]
struct Gcra {
    /// When the allowance is next fully refilled; `None` until first used.
    tat: Option<Instant>,
}

impl Gcra {
    /// The arrival time a further event would move this limiter to, if it is
    /// allowed now.
    fn admit(self, now: Instant, interval: Duration, burst: u32) -> Option<Instant> {
        let tat = self.tat.map_or(now, |tat| tat.max(now));
        let next = tat.checked_add(interval)?;
        (next.saturating_duration_since(now) <= interval.saturating_mul(burst)).then_some(next)
    }

    /// Whether the allowance has fully refilled.
    fn is_idle(self, now: Instant) -> bool {
        self.tat.is_none_or(|tat| tat <= now)
    }
}

/// One peer's busy-reply allowance.
#[derive(Debug, Default, Clone, Copy)]
struct PeerAllowance {
    rate: Gcra,
    /// Busy replies to this peer being sent now.
    in_flight: u32,
}

impl PeerAllowance {
    /// Forgetting it loses nothing: its allowance is full and nothing is in
    /// flight.
    fn is_idle(self, now: Instant) -> bool {
        self.in_flight == 0 && self.rate.is_idle(now)
    }
}

#[derive(Debug, Default)]
struct LimiterState {
    global: Gcra,
    peers: HashMap<PeerId, PeerAllowance>,
}

/// Why a busy reply was not allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusyReplyDenied {
    /// Over the per-peer or global rate, or the table of peers is full.
    RateLimited,
    /// The most busy replies to this peer that may be in flight are still
    /// being sent.
    PeerInFlight,
}

/// Bounds how many busy replies a responder sends: per peer and overall, by
/// rate, and how many to one peer may be in flight at once.
///
/// Synchronous and short, so it can be asked on the serial message loop.
#[derive(Debug, Default)]
pub struct FetchBusyReplyLimiter {
    state: Mutex<LimiterState>,
}

impl FetchBusyReplyLimiter {
    /// A limiter with every allowance full.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow one busy reply to `peer` at `now`, if its allowance, the global
    /// one and its in-flight limit all permit. Both rate allowances are spent
    /// together on a grant and neither on a denial. The returned grant holds
    /// one of the peer's in-flight places until it is dropped, which the caller
    /// does when the send ends.
    ///
    /// # Errors
    ///
    /// Returns why the reply is not allowed.
    pub fn try_acquire(
        self: &Arc<Self>,
        peer: &PeerId,
        now: Instant,
    ) -> Result<BusyReplyGrant, BusyReplyDenied> {
        let mut state = self.state.lock();
        if !state.peers.contains_key(peer) && state.peers.len() >= MAX_TRACKED_PEERS {
            state.peers.retain(|_, allowance| !allowance.is_idle(now));
            if state.peers.len() >= MAX_TRACKED_PEERS {
                return Err(BusyReplyDenied::RateLimited);
            }
        }
        let allowance = state.peers.get(peer).copied().unwrap_or_default();
        if allowance.in_flight >= PEER_BURST {
            return Err(BusyReplyDenied::PeerInFlight);
        }
        let peer_next = allowance
            .rate
            .admit(now, PEER_INTERVAL, PEER_BURST)
            .ok_or(BusyReplyDenied::RateLimited)?;
        let global_next = state
            .global
            .admit(now, GLOBAL_INTERVAL, GLOBAL_BURST)
            .ok_or(BusyReplyDenied::RateLimited)?;
        state.global.tat = Some(global_next);
        state.peers.insert(
            *peer,
            PeerAllowance {
                rate: Gcra {
                    tat: Some(peer_next),
                },
                in_flight: allowance.in_flight.saturating_add(1),
            },
        );
        Ok(BusyReplyGrant {
            limiter: Arc::clone(self),
            peer: *peer,
        })
    }

    fn release(&self, peer: &PeerId) {
        if let Some(allowance) = self.state.lock().peers.get_mut(peer) {
            allowance.in_flight = allowance.in_flight.saturating_sub(1);
        }
    }

    /// How many peers are tracked now.
    #[cfg(test)]
    fn tracked_peers(&self) -> usize {
        self.state.lock().peers.len()
    }
}

/// A granted busy reply. Holds one of the peer's in-flight places until
/// dropped.
#[derive(Debug)]
pub struct BusyReplyGrant {
    limiter: Arc<FetchBusyReplyLimiter>,
    peer: PeerId,
}

impl Drop for BusyReplyGrant {
    fn drop(&mut self) {
        self.limiter.release(&self.peer);
    }
}

/// What one busy answer means for its source at this requester.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BusyAnswer {
    /// How long the source is now put last.
    pub cooling_for: Duration,
    /// Whether the answer is past the source's neutral allowance, and so is
    /// handled as the silent refusal it replaces.
    pub charged: bool,
}

/// One source's busy answers to this requester since it last served it.
#[derive(Debug, Clone, Copy)]
struct SourceBusy {
    /// Busy answers in its current busy spell, which set its cooldown.
    strikes: u32,
    /// Busy answers since it last served this requester, however long ago:
    /// what spends its neutral allowance.
    unserved: u32,
    /// Until when it is put last.
    cooling_until: Instant,
    /// When it last answered busy.
    last_busy: Instant,
}

impl SourceBusy {
    fn is_cooling(self, now: Instant) -> bool {
        now < self.cooling_until
    }

    fn spell_over(self, now: Instant) -> bool {
        !self.is_cooling(now) && now.saturating_duration_since(self.last_busy) >= BUSY_SPELL_GAP
    }
}

/// Which sources recently answered this requester busy, until when they
/// should be asked last, and which have used up their neutral allowance.
///
/// Mostly local scheduling: a holder that just refused is the worst place to
/// send the next fetch, and one that keeps refusing is put last for longer
/// each time. The fetch scheduler reads it to start or retry a key on another
/// free holder first, and never to withhold one: a key whose every free holder
/// is cooling still starts on the first of them, and then waits out that
/// holder's busy answer like any other. So per requester it lowers how often
/// a busy holder is asked; the hard bound is the busy wait per fetch slot.
///
/// The same record counts a source's busy answers in a row, across all keys,
/// against [`FETCH_BUSY_NEUTRAL_ALLOWANCE`]. It does not touch trust itself;
/// it tells the caller which busy answer is past the allowance. Only serving
/// clears the record, and so restores the allowance: neither time nor a full
/// table does. The table is not saved, so a restart clears it.
/// Synchronous and short, so it is safe to consult while holding the fetch
/// queues lock.
#[derive(Debug, Default)]
pub struct SourceBusyTracker {
    sources: Mutex<HashMap<PeerId, SourceBusy>>,
}

impl SourceBusyTracker {
    /// A tracker that knows no busy source.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a busy answer from `source` at `now`. `wait` is the busy wait
    /// before any cap from the attempt's own timeout.
    ///
    /// Returns how long the source is now put last: `wait` the first time,
    /// doubling with each further busy answer in the same busy spell, up to a
    /// minute. A cooldown already running is never shortened, so when it
    /// outlasts the new one, what is left of it is returned. Also returns
    /// whether this answer is past the source's
    /// [`FETCH_BUSY_NEUTRAL_ALLOWANCE`]. When the table is full and holds no
    /// record of `source`, the answer is charged and nothing is recorded.
    pub fn record_busy(&self, source: &PeerId, now: Instant, wait: Duration) -> BusyAnswer {
        let mut sources = self.sources.lock();
        if !sources.contains_key(source) && sources.len() >= MAX_TRACKED_SOURCES {
            // Forgetting any record would restore its source's allowance, so
            // with no room this answer gets none.
            return BusyAnswer {
                cooling_for: Duration::ZERO,
                charged: true,
            };
        }
        let record = sources.entry(*source).or_insert(SourceBusy {
            strikes: 0,
            unserved: 0,
            cooling_until: now,
            last_busy: now,
        });
        if record.spell_over(now) {
            record.strikes = 0;
        }
        record.strikes = record.strikes.saturating_add(1);
        record.unserved = record.unserved.saturating_add(1);
        let doublings = record.strikes.saturating_sub(1).min(MAX_COOLDOWN_DOUBLINGS);
        let cooldown = wait
            .saturating_mul(1u32 << doublings)
            .min(MAX_SOURCE_COOLDOWN);
        let until = now.checked_add(cooldown).unwrap_or(now);
        record.cooling_until = record.cooling_until.max(until);
        record.last_busy = now;
        let answer = BusyAnswer {
            cooling_for: record.cooling_until.saturating_duration_since(now),
            charged: record.unserved > FETCH_BUSY_NEUTRAL_ALLOWANCE,
        };
        audit_metrics::set_fetch_busy_sources_tracked(sources.len());
        answer
    }

    /// `source` served this requester: forget its busy record, which restores
    /// its neutral allowance.
    pub fn record_served(&self, source: &PeerId) {
        let mut sources = self.sources.lock();
        if sources.remove(source).is_some() {
            audit_metrics::set_fetch_busy_sources_tracked(sources.len());
        }
    }

    /// Whether `source` should be asked last at `now`.
    #[must_use]
    pub fn is_cooling(&self, source: &PeerId, now: Instant) -> bool {
        self.sources
            .lock()
            .get(source)
            .is_some_and(|record| record.is_cooling(now))
    }

    /// Busy answers from `source` since it last served this requester, as far
    /// as it is remembered.
    #[must_use]
    pub fn unserved_busy(&self, source: &PeerId) -> u32 {
        self.sources
            .lock()
            .get(source)
            .map_or(0, |record| record.unserved)
    }

    /// When `source` last answered busy, if it is still remembered.
    #[must_use]
    pub fn last_busy(&self, source: &PeerId) -> Option<Instant> {
        self.sources
            .lock()
            .get(source)
            .map(|record| record.last_busy)
    }

    /// How many sources are tracked now.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sources.lock().len()
    }

    /// Whether no source is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sources.lock().is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn peer(i: u32) -> PeerId {
        let mut bytes = [0u8; 32];
        for (byte, value) in bytes.iter_mut().zip(i.to_le_bytes()) {
            *byte = value;
        }
        PeerId::from_bytes(bytes)
    }

    fn limiter() -> Arc<FetchBusyReplyLimiter> {
        Arc::new(FetchBusyReplyLimiter::new())
    }

    /// Grant and immediately end the send, as a reply that went out at once.
    fn grant(limiter: &Arc<FetchBusyReplyLimiter>, p: &PeerId, now: Instant) -> bool {
        limiter.try_acquire(p, now).is_ok()
    }

    #[test]
    fn busy_wait_spans_the_jitter_range() {
        let remaining = Duration::from_secs(30);
        assert_eq!(busy_wait(remaining, Duration::ZERO), FETCH_BUSY_WAIT_MIN);
        assert_eq!(
            busy_wait(remaining, FETCH_BUSY_WAIT_SPREAD),
            FETCH_BUSY_WAIT_MAX
        );
        assert_eq!(
            busy_wait(remaining, Duration::from_secs(2)),
            FETCH_BUSY_WAIT_MIN + Duration::from_secs(2)
        );
        // Jitter past the spread is clamped, not added.
        assert_eq!(
            busy_wait(remaining, Duration::from_hours(1)),
            FETCH_BUSY_WAIT_MAX
        );
    }

    #[test]
    fn busy_wait_never_outlasts_the_fetch_timeout() {
        assert_eq!(
            busy_wait(Duration::from_secs(3), FETCH_BUSY_WAIT_SPREAD),
            Duration::from_secs(3)
        );
        assert_eq!(
            busy_wait(Duration::ZERO, FETCH_BUSY_WAIT_SPREAD),
            Duration::ZERO
        );
    }

    #[test]
    fn a_busy_answer_never_waits_past_the_fetch_timeout() {
        let neutral = BusyAnswer {
            cooling_for: FETCH_BUSY_WAIT_MIN,
            charged: false,
        };
        let charged = BusyAnswer {
            cooling_for: FETCH_BUSY_WAIT_MIN,
            charged: true,
        };
        let sent = Instant::now();
        let deadline = sent + Duration::from_secs(30);
        // A prompt answer: the busy wait within the allowance, the rest of the
        // timeout past it.
        assert_eq!(
            busy_wake(neutral, FETCH_BUSY_WAIT_MAX, sent, deadline),
            sent + FETCH_BUSY_WAIT_MAX
        );
        assert_eq!(
            busy_wake(charged, FETCH_BUSY_WAIT_MAX, sent, deadline),
            deadline
        );
        // A late answer, a second before the deadline, holds the slot for that
        // second and no more; one after it, not at all.
        for now in [
            sent + Duration::from_secs(29),
            deadline + Duration::from_secs(5),
        ] {
            for answer in [neutral, charged] {
                assert_eq!(
                    busy_wake(answer, FETCH_BUSY_WAIT_MAX, now, deadline),
                    deadline
                );
            }
        }
    }

    #[test]
    fn a_peer_gets_its_burst_then_one_reply_per_interval() {
        let limiter = limiter();
        let p = peer(1);
        let t0 = Instant::now();
        for _ in 0..PEER_BURST {
            assert!(grant(&limiter, &p, t0));
        }
        assert_eq!(
            limiter.try_acquire(&p, t0).err(),
            Some(BusyReplyDenied::RateLimited)
        );
        assert!(!grant(&limiter, &p, t0 + PEER_INTERVAL / 2));
        assert!(grant(&limiter, &p, t0 + PEER_INTERVAL));
        assert!(!grant(&limiter, &p, t0 + PEER_INTERVAL));
        // A long quiet spell refills only up to the burst, never beyond it.
        let later = t0 + PEER_INTERVAL * 100;
        for _ in 0..PEER_BURST {
            assert!(grant(&limiter, &p, later));
        }
        assert!(!grant(&limiter, &p, later));
    }

    #[test]
    fn at_most_a_burst_in_flight_per_peer() {
        let limiter = limiter();
        let p = peer(1);
        let t0 = Instant::now();
        let held: Vec<BusyReplyGrant> = (0..PEER_BURST)
            .map(|_| limiter.try_acquire(&p, t0).expect("within the burst"))
            .collect();
        // Long enough later that the rate allows more, but the sends have not
        // ended: the in-flight limit refuses.
        let later = t0 + PEER_INTERVAL * 10;
        assert_eq!(
            limiter.try_acquire(&p, later).err(),
            Some(BusyReplyDenied::PeerInFlight)
        );
        // Another peer is not affected.
        assert!(grant(&limiter, &peer(2), later));
        drop(held);
        assert!(grant(&limiter, &p, later));
    }

    #[test]
    fn one_peer_exhausting_its_allowance_leaves_others_theirs() {
        let limiter = limiter();
        let t0 = Instant::now();
        for _ in 0..10 {
            let _ = grant(&limiter, &peer(1), t0);
        }
        assert!(grant(&limiter, &peer(2), t0));
    }

    #[test]
    fn the_global_allowance_caps_every_peer_together() {
        let limiter = limiter();
        let t0 = Instant::now();
        let granted = (0..1_000u32)
            .filter(|i| grant(&limiter, &peer(*i), t0))
            .count();
        assert_eq!(granted, usize::try_from(GLOBAL_BURST).unwrap());
        // Refills at the global rate: one second later, one second's worth.
        let t1 = t0 + Duration::from_secs(1);
        let granted = (1_000..2_000u32)
            .filter(|i| grant(&limiter, &peer(*i), t1))
            .count();
        let per_second = Duration::from_secs(1).as_nanos() / GLOBAL_INTERVAL.as_nanos();
        assert_eq!(granted, usize::try_from(per_second).unwrap());
    }

    #[test]
    fn a_global_refusal_spends_nothing_from_the_peer() {
        let limiter = limiter();
        let t0 = Instant::now();
        for i in 0..GLOBAL_BURST {
            assert!(grant(&limiter, &peer(i), t0));
        }
        let p = peer(100_000);
        assert!(!grant(&limiter, &p, t0));
        assert_eq!(
            limiter.tracked_peers(),
            usize::try_from(GLOBAL_BURST).unwrap()
        );
        // Once the global allowance refills, the peer still has its whole burst.
        let t1 = t0 + Duration::from_secs(1);
        for _ in 0..PEER_BURST {
            assert!(grant(&limiter, &p, t1));
        }
    }

    #[test]
    fn the_peer_table_stays_bounded_and_forgets_only_idle_peers() {
        let limiter = limiter();
        let mut now = Instant::now();
        let mut next_peer = 0u32;
        // Fill the table with replies still in flight, pacing to stay inside
        // the global allowance.
        let mut held = Vec::new();
        while held.len() < MAX_TRACKED_PEERS {
            match limiter.try_acquire(&peer(next_peer), now) {
                Ok(grant) => {
                    held.push(grant);
                    next_peer += 1;
                }
                Err(_) => now += GLOBAL_INTERVAL,
            }
        }
        assert_eq!(limiter.tracked_peers(), MAX_TRACKED_PEERS);
        // No entry can be forgotten, so a newcomer is refused rather than
        // tracked, although the global allowance has long refilled.
        let newcomer = peer(u32::MAX);
        let later = now + Duration::from_secs(10);
        assert_eq!(
            limiter.try_acquire(&newcomer, later).err(),
            Some(BusyReplyDenied::RateLimited)
        );
        assert_eq!(limiter.tracked_peers(), MAX_TRACKED_PEERS);
        // Once those replies end, idle entries make room.
        drop(held);
        assert!(grant(&limiter, &newcomer, later));
        assert!(limiter.tracked_peers() <= MAX_TRACKED_PEERS);
    }

    #[test]
    fn a_peer_with_a_reply_in_flight_is_never_forgotten() {
        let limiter = limiter();
        let t0 = Instant::now();
        let held: Vec<BusyReplyGrant> = (0..PEER_BURST)
            .map(|_| limiter.try_acquire(&peer(0), t0).expect("grant"))
            .collect();
        let mut now = t0;
        for i in 1..u32::try_from(MAX_TRACKED_PEERS).unwrap() {
            while !grant(&limiter, &peer(i), now) {
                now += GLOBAL_INTERVAL;
            }
        }
        // Long after, everyone else is idle and a full table sheds them, but
        // never the peer whose reply is still in flight.
        let later = now + Duration::from_hours(1);
        assert!(grant(&limiter, &peer(u32::MAX), later));
        assert_eq!(
            limiter.try_acquire(&peer(0), later).err(),
            Some(BusyReplyDenied::PeerInFlight)
        );
        drop(held);
        assert!(grant(&limiter, &peer(0), later));
    }

    const WAIT: Duration = Duration::from_secs(5);

    #[test]
    fn a_busy_source_cools_for_the_wait() {
        let tracker = SourceBusyTracker::new();
        let (a, b) = (peer(1), peer(2));
        let t0 = Instant::now();
        assert!(!tracker.is_cooling(&a, t0));
        assert_eq!(tracker.record_busy(&a, t0, WAIT).cooling_for, WAIT);
        assert!(tracker.is_cooling(&a, t0));
        assert!(!tracker.is_cooling(&b, t0));
        // Cooling ends after the wait.
        assert!(!tracker.is_cooling(&a, t0 + WAIT));
    }

    #[test]
    fn a_source_that_stays_busy_cools_longer_up_to_the_cap() {
        let tracker = SourceBusyTracker::new();
        let a = peer(1);
        let t0 = Instant::now();
        let cooldowns: Vec<Duration> = (0..6)
            .map(|_| tracker.record_busy(&a, t0, WAIT).cooling_for)
            .collect();
        assert_eq!(
            cooldowns,
            vec![WAIT, WAIT * 2, WAIT * 4, WAIT * 8, WAIT * 8, WAIT * 8]
        );
        // A longer wait reaches the cap.
        let b = peer(2);
        let long = Duration::from_secs(10);
        for _ in 0..4 {
            tracker.record_busy(&b, t0, long);
        }
        assert_eq!(
            tracker.record_busy(&b, t0, long).cooling_for,
            MAX_SOURCE_COOLDOWN
        );
    }

    #[test]
    fn a_running_cooldown_is_never_shortened() {
        let tracker = SourceBusyTracker::new();
        let a = peer(1);
        let t0 = Instant::now();
        for _ in 0..4 {
            tracker.record_busy(&a, t0, Duration::from_secs(10));
        }
        // Cooling until t0 + 60 s now. A later busy answer with a tiny wait
        // would end far sooner; the running cooldown stands, and what is left
        // of it is what the caller is told.
        assert_eq!(
            tracker
                .record_busy(&a, t0 + Duration::from_secs(1), Duration::from_millis(1))
                .cooling_for,
            Duration::from_secs(59)
        );
        assert!(tracker.is_cooling(&a, t0 + Duration::from_secs(59)));
    }

    #[test]
    fn serving_once_clears_the_record() {
        let tracker = SourceBusyTracker::new();
        let a = peer(1);
        let t0 = Instant::now();
        for _ in 0..3 {
            tracker.record_busy(&a, t0, WAIT);
        }
        tracker.record_served(&a);
        assert!(!tracker.is_cooling(&a, t0));
        assert!(tracker.is_empty());
        assert_eq!(tracker.record_busy(&a, t0, WAIT).cooling_for, WAIT);
    }

    #[test]
    fn a_new_busy_spell_starts_the_cooldown_over() {
        let tracker = SourceBusyTracker::new();
        let a = peer(1);
        let t0 = Instant::now();
        for _ in 0..3 {
            tracker.record_busy(&a, t0, WAIT);
        }
        // Long after its last busy answer, the next one starts a new spell:
        // its cooldown is the first one's again.
        let later = t0 + BUSY_SPELL_GAP + MAX_SOURCE_COOLDOWN;
        assert_eq!(tracker.record_busy(&a, later, WAIT).cooling_for, WAIT);
        assert_eq!(tracker.unserved_busy(&a), 4);
    }

    /// A holder that keeps the data but answers busy to every fetch, one
    /// every busy wait for over an hour. The record is per source, so these
    /// answers count together whichever keys they answer. Only its first
    /// `FETCH_BUSY_NEUTRAL_ALLOWANCE` answers are free.
    #[test]
    fn a_holder_that_never_serves_is_charged_past_its_allowance() {
        let tracker = SourceBusyTracker::new();
        let holder = peer(1);
        let t0 = Instant::now();
        let neutral = usize::try_from(FETCH_BUSY_NEUTRAL_ALLOWANCE).unwrap();
        let charged: Vec<bool> = (0..1_000u32)
            .map(|i| tracker.record_busy(&holder, t0 + WAIT * i, WAIT).charged)
            .collect();
        assert!(charged.iter().take(neutral).all(|c| !c));
        assert!(charged.iter().skip(neutral).all(|c| *c));
    }

    /// Two answers at once, one for each request in the reply burst, spend
    /// two of the allowance: it counts answers, not rounds.
    #[test]
    fn answers_that_arrive_together_each_spend_the_allowance() {
        let tracker = SourceBusyTracker::new();
        let holder = peer(1);
        let t0 = Instant::now();
        for _ in 0..FETCH_BUSY_NEUTRAL_ALLOWANCE {
            assert!(!tracker.record_busy(&holder, t0, WAIT).charged);
        }
        assert!(tracker.record_busy(&holder, t0, WAIT).charged);
    }

    /// Honest overload comes and goes: a holder that serves this requester
    /// once between busy spells, each as long as the allowance, is never
    /// charged however many spells there are.
    #[test]
    fn a_holder_that_serves_between_busy_spells_is_never_charged() {
        let tracker = SourceBusyTracker::new();
        let holder = peer(1);
        let mut now = Instant::now();
        for _ in 0..100 {
            for _ in 0..FETCH_BUSY_NEUTRAL_ALLOWANCE {
                assert!(!tracker.record_busy(&holder, now, WAIT).charged);
                now += WAIT;
            }
            tracker.record_served(&holder);
        }
    }

    /// Serving once restores the whole allowance, and another source serving
    /// does not.
    #[test]
    fn serving_once_restores_the_allowance() {
        let tracker = SourceBusyTracker::new();
        let (holder, other) = (peer(1), peer(2));
        let t0 = Instant::now();
        for _ in 0..FETCH_BUSY_NEUTRAL_ALLOWANCE {
            tracker.record_busy(&holder, t0, WAIT);
        }
        // Another holder serving changes nothing for this one.
        tracker.record_served(&other);
        assert!(tracker.record_busy(&holder, t0, WAIT).charged);
        tracker.record_served(&holder);
        for _ in 0..FETCH_BUSY_NEUTRAL_ALLOWANCE {
            assert!(!tracker.record_busy(&holder, t0, WAIT).charged);
        }
        assert!(tracker.record_busy(&holder, t0, WAIT).charged);
    }

    /// Time does not restore the allowance: a holder asked only rarely, long
    /// after each busy spell has ended, still uses it up across spells and is
    /// charged until it serves.
    #[test]
    fn time_alone_never_restores_the_allowance() {
        let tracker = SourceBusyTracker::new();
        let holder = peer(1);
        let t0 = Instant::now();
        let apart = BUSY_SPELL_GAP * 6;
        let charged: Vec<bool> = (0..=FETCH_BUSY_NEUTRAL_ALLOWANCE + 2)
            .map(|i| {
                let answer = tracker.record_busy(&holder, t0 + apart * i, WAIT);
                // Every answer starts a new spell, so each cools only the wait.
                assert_eq!(answer.cooling_for, WAIT);
                answer.charged
            })
            .collect();
        let neutral = usize::try_from(FETCH_BUSY_NEUTRAL_ALLOWANCE).unwrap();
        assert!(charged.iter().take(neutral).all(|c| !c));
        assert!(charged.iter().skip(neutral).all(|c| *c));
    }

    /// A full table forgets nothing, so many holders taking turns to answer
    /// busy cannot push one another's records out to start again. A newcomer
    /// is charged instead, and a tracked holder keeps counting.
    #[test]
    fn a_full_table_forgets_nothing_and_charges_newcomers() {
        let tracker = SourceBusyTracker::new();
        let t0 = Instant::now();
        let max = u32::try_from(MAX_TRACKED_SOURCES).unwrap();
        for i in 0..max {
            assert!(!tracker.record_busy(&peer(i), t0, WAIT).charged);
        }
        assert_eq!(tracker.len(), MAX_TRACKED_SOURCES);
        // One more holder than the table holds, all taking turns, long apart:
        // every later round is charged for the newcomer, and nobody's count
        // starts again.
        let newcomer = peer(max);
        let mut now = t0;
        for _ in 0..=FETCH_BUSY_NEUTRAL_ALLOWANCE {
            now += BUSY_SPELL_GAP * 2;
            assert_eq!(
                tracker.record_busy(&newcomer, now, WAIT),
                BusyAnswer {
                    cooling_for: Duration::ZERO,
                    charged: true,
                }
            );
            for i in 0..max {
                tracker.record_busy(&peer(i), now, WAIT);
            }
        }
        assert_eq!(tracker.len(), MAX_TRACKED_SOURCES);
        assert!(!tracker.is_cooling(&newcomer, now));
        assert_eq!(tracker.unserved_busy(&newcomer), 0);
        assert!(
            (0..max).all(|i| tracker.unserved_busy(&peer(i)) == FETCH_BUSY_NEUTRAL_ALLOWANCE + 2)
        );
        assert!(tracker.record_busy(&peer(0), now, WAIT).charged);
        // Serving makes room again.
        tracker.record_served(&peer(0));
        assert!(!tracker.record_busy(&newcomer, now, WAIT).charged);
    }
}
