//! Swarm rendezvous: the node introduces clients that are downloading the
//! same file, so they can share its records with each other.
//!
//! A client announces itself in a *room* (a file) at the nodes closest to
//! the room's key and hands them WebRTC offers. The node passes each offer to
//! another member and carries the answer back; the two clients then talk
//! directly and records never pass through the node. The node stays the last
//! seed: whatever no client has is fetched from it as before.
//!
//! The rules, all enforced here:
//! - members are named by the node ([`MemberId`]), one per connection and
//!   room, so a client cannot speak for another;
//! - an answer is passed on only for an offer this node delivered to the
//!   answering member, once, before the offer expires;
//! - only `{offer_id, sdp}` is relayed, never anything else a client sent;
//! - rooms, members, rooms per connection, remembered offers, waiting
//!   announces and stored SDP bytes are all capped. The caps are fixed:
//!   swarm work is small, and a node that is short of room simply refuses,
//!   which leaves its clients fetching from nodes alone.
//!
//! Signals for a member wait in a small inbox until its next announce, which
//! may wait for them (a long poll). A waiting announce holds no lock and
//! ends at the deadline, on the first signal, or when the node shuts down.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ant_protocol::chunk::{ChunkMessageBody, ProtocolError};
use ant_protocol::swarm::{
    constrain_swarm_sdp, is_global_ip, MemberId, Membership, NodeId, OfferId, RoomKey,
    SwarmAnnounceRequest, SwarmAnnounceResponse, SwarmAnswerRequest, SwarmAnswerResponse,
    SwarmLeaveRequest, SwarmLeaveResponse, SwarmRefusal, SwarmSignal, MAX_SWARM_ICE_SERVERS,
    MAX_SWARM_ICE_SERVER_BYTES, MAX_SWARM_INBOX, MAX_SWARM_REPLY_SDP_BYTES, SWARM_SIGNAL_TTL_MS,
};
use parking_lot::{Mutex, RwLock};
use rand::seq::SliceRandom;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::logging::debug;

/// Rooms one node hosts.
pub const MAX_ROOMS: usize = 4096;
/// Members in one room.
pub const MAX_MEMBERS_PER_ROOM: usize = 256;
/// Members across every room.
pub const MAX_MEMBERS: usize = 16_384;
/// Rooms one connection may be in.
pub const MAX_ROOMS_PER_SESSION: usize = 4;
/// Members from one host (an IPv4 address or an IPv6 /64) across every
/// room: a native client's identities cost nothing to make, so a host could
/// otherwise take every place with new ones.
pub const MAX_MEMBERS_PER_HOST: usize = 64;
/// Signals waiting for one member.
pub const MAX_INBOX_PER_MEMBER: usize = MAX_SWARM_INBOX;
/// Unanswered offers remembered for one member. Past it, its new offers are
/// not passed on until older ones are answered or expire.
pub const MAX_PENDING_PER_MEMBER: usize = 32;
/// SDP bytes held in every inbox together.
pub const MAX_STORED_SDP_BYTES: usize = 16 * 1024 * 1024;
/// SDP bytes held for the offers and answers of one host's members, so one
/// host cannot take the whole budget and stop every other introduction.
pub const MAX_STORED_SDP_BYTES_PER_HOST: usize = MAX_STORED_SDP_BYTES / 8;
/// Announces waiting for a signal at once; past it, announces reply at once.
pub const MAX_WAITING: usize = 1024;
/// A member that has not announced for this long leaves its room.
pub const MEMBER_TTL: Duration = Duration::from_secs(60);
/// How long a delivered offer waits for its answer, and a signal for its
/// member's next announce: the protocol's, which clients check their own
/// answering time against.
pub const SIGNAL_TTL: Duration = Duration::from_millis(SWARM_SIGNAL_TTL_MS);
/// Client addresses remembered as recent announcers, which the node's STUN
/// responder answers.
pub const MAX_STUN_SOURCES: usize = 16_384;
/// Memberships that ended remembered, in all, per connection and per host.
const MAX_ENDED_MEMBERSHIPS: usize = MAX_MEMBERS;
const MAX_ENDED_PER_SESSION: usize = 64;
const MAX_ENDED_PER_HOST: usize = 4 * MAX_ENDED_PER_SESSION;
/// How long an ended membership is remembered: as long as a request sent
/// before it ended can still be taken. A native request's signed time may be
/// up to [`MAX_REQUEST_SKEW`] ahead of this node's clock and is taken until
/// it is that far behind, so twice the skew, and a little for rounding.
const ENDED_MEMBERSHIP_TTL: Duration = Duration::from_secs(2 * MAX_REQUEST_SKEW.as_secs() + 2);
/// Closed connections remembered, and for how long: longer than any request
/// takes to reach its handler.
const MAX_CLOSED_SESSIONS: usize = MAX_MEMBERS;
const CLOSED_SESSION_TTL: Duration = Duration::from_secs(60);
/// How far a native client's signed timestamp may be from this node's clock.
/// A wide window: clients' clocks drift, and a request outside it only costs
/// the client its swarm, not its reads.
pub const MAX_REQUEST_SKEW: Duration = Duration::from_mins(10);
/// How much older than a native client's newest request one of its requests
/// may be, for requests overtaking each other on the way.
const REQUEST_REORDER: u64 = 5;
/// Request ids remembered per native client within [`REQUEST_REORDER`].
const MAX_RECENT_REQUESTS: usize = 256;
/// Native clients whose requests are remembered.
const MAX_REQUEST_HISTORIES: usize = MAX_MEMBERS;
/// Native clients of one host whose requests are remembered: identities cost
/// nothing to make, so a host could otherwise push every other client's
/// history out.
const MAX_HISTORIES_PER_HOST: usize = 4 * MAX_MEMBERS_PER_HOST;

/// A native client's recent requests, to refuse one sent again. Its own
/// requests are the only ones that can change it.
#[derive(Default)]
struct RequestHistory {
    /// The newest signed timestamp seen.
    latest: u64,
    /// Ids signed within [`REQUEST_REORDER`] of `latest`, with their times.
    recent: VecDeque<(u64, u64)>,
    /// When it was made, among all histories.
    number: u64,
    /// The client's host, if known.
    host: Option<IpAddr>,
}

impl RequestHistory {
    /// Records a request; `false` if it was here, or is much older than the
    /// newest.
    fn note(&mut self, request_id: u64, signed_at: u64) -> bool {
        if signed_at.saturating_add(REQUEST_REORDER) < self.latest
            || self.recent.iter().any(|(_, id)| *id == request_id)
        {
            return false;
        }
        self.latest = self.latest.max(signed_at);
        self.recent.push_back((signed_at, request_id));
        let oldest = self.latest.saturating_sub(REQUEST_REORDER);
        self.recent.retain(|(at, _)| *at >= oldest);
        while self.recent.len() > MAX_RECENT_REQUESTS {
            self.recent.pop_front();
        }
        true
    }
}

/// Native clients' request histories: at most [`MAX_HISTORIES_PER_HOST`] per
/// host and [`MAX_REQUEST_HISTORIES`] in all, the oldest made forgotten first,
/// and each forgotten once nothing it holds could pass the age check.
#[derive(Default)]
struct Histories {
    by_peer: HashMap<[u8; 32], RequestHistory>,
    /// The histories in the order they were made, numbered, so an entry for
    /// a history forgotten since never removes a newer one of its client.
    order: VecDeque<([u8; 32], u64)>,
    made: u64,
    by_host: HashMap<IpAddr, usize>,
}

impl Histories {
    fn forget(&mut self, peer: &[u8; 32]) {
        let Some(history) = self.by_peer.remove(peer) else {
            return;
        };
        if let Some(host) = history.host {
            if let Some(count) = self.by_host.get_mut(&host) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.by_host.remove(&host);
                }
            }
        }
    }

    /// Starts `peer`'s history, unless its host has all it may have. With
    /// every place taken, the oldest history goes.
    fn start(&mut self, peer: [u8; 32], host: Option<IpAddr>) -> bool {
        let host_full = host.is_some_and(|host| {
            self.by_host.get(&host).copied().unwrap_or(0) >= MAX_HISTORIES_PER_HOST
        });
        if host_full {
            return false;
        }
        while self.by_peer.len() >= MAX_REQUEST_HISTORIES {
            let Some((oldest, number)) = self.order.pop_front() else {
                break;
            };
            if self.by_peer.get(&oldest).map(|history| history.number) == Some(number) {
                self.forget(&oldest);
            }
        }
        self.made = self.made.wrapping_add(1);
        self.by_peer.insert(
            peer,
            RequestHistory {
                number: self.made,
                host,
                ..RequestHistory::default()
            },
        );
        self.order.push_back((peer, self.made));
        if let Some(host) = host {
            *self.by_host.entry(host).or_default() += 1;
        }
        true
    }

    /// Forgets the histories whose newest request was signed before
    /// `oldest`: nothing they hold could pass the age check now.
    fn forget_older_than(&mut self, oldest: u64) {
        let idle: Vec<[u8; 32]> = self
            .by_peer
            .iter()
            .filter(|(_, history)| history.latest < oldest)
            .map(|(peer, _)| *peer)
            .collect();
        for peer in &idle {
            self.forget(peer);
        }
        let by_peer = &self.by_peer;
        self.order.retain(|(peer, number)| {
            by_peer.get(peer).map(|history| history.number) == Some(*number)
        });
    }
}

/// The connection a request came on. Members are tied to it: a native
/// client's authenticated peer id, or a browser connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwarmSession {
    /// A native client, by its authenticated peer id.
    Native([u8; 32]),
    /// A browser, by its WebRTC Direct connection number on this node.
    Browser(u64),
}

/// Counters for metrics and logs.
#[derive(Debug, Default)]
pub struct SwarmCounters {
    /// Announces received.
    pub announces: AtomicU64,
    /// Answers received.
    pub answers: AtomicU64,
    /// Offers handed to a member.
    pub offers_delivered: AtomicU64,
    /// Offers not handed on: no room in an inbox, a pending cap, or the
    /// stored-SDP budget.
    pub offers_undelivered: AtomicU64,
    /// Answers handed back to the member that made the offer.
    pub answers_delivered: AtomicU64,
    /// Answers with no matching offer, or that could not be kept.
    pub answers_unmatched: AtomicU64,
    /// Announces refused by a cap.
    pub refused: AtomicU64,
    /// Members dropped because they stopped announcing.
    pub members_expired: AtomicU64,
}

/// Counts at one moment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SwarmStats {
    /// Rooms with at least one member.
    pub rooms: usize,
    /// Members across all rooms.
    pub members: usize,
    /// Offers delivered and waiting for an answer.
    pub pending_offers: usize,
    /// SDP bytes held in inboxes.
    pub stored_sdp_bytes: usize,
    /// Announces waiting for a signal.
    pub waiting: usize,
}

/// One close of a native client's connection.
#[derive(Debug, Clone, Copy)]
struct Closed {
    at: Instant,
    number: u64,
}

/// A membership the client ended, see [`State::ended`].
#[derive(Clone, Copy)]
struct Ended {
    membership: Membership,
    /// When it was noted, among all ended memberships.
    number: u64,
    host: Option<IpAddr>,
}

struct Pending {
    offer_id: OfferId,
    to: MemberId,
    expires: Instant,
}

struct Queued {
    signal: SwarmSignal,
    bytes: usize,
    /// The host of the member that sent it, whose share of the budget it
    /// takes.
    host: Option<IpAddr>,
    expires: Instant,
}

struct Member {
    session: SwarmSession,
    /// The client's membership this member is: a newer one takes its place,
    /// and only a leave naming it ends it.
    membership: Membership,
    /// The host it announced from, if known: see [`MAX_MEMBERS_PER_HOST`].
    host: Option<IpAddr>,
    last_seen: Instant,
    inbox: VecDeque<Queued>,
    pending: VecDeque<Pending>,
    /// Woken, for every announce waiting then, when a signal arrives or the
    /// member is dropped.
    wake: Arc<Notify>,
    /// Whether an announce of this member is waiting: one at a time.
    waiting: bool,
}

#[derive(Default)]
struct Room {
    members: HashMap<MemberId, Member>,
    by_session: HashMap<SwarmSession, MemberId>,
}

#[derive(Default)]
struct State {
    rooms: HashMap<RoomKey, Room>,
    sessions: HashMap<SwarmSession, Vec<RoomKey>>,
    /// When native clients' connections last closed, so a request of theirs
    /// still being handled cannot act after the close (a browser connection's
    /// own token tells), and the closes in the order they happened, to forget
    /// the old ones in constant time.
    closed: HashMap<SwarmSession, Closed>,
    closed_order: VecDeque<(SwarmSession, Closed)>,
    /// Numbers closes, so an old queue entry never removes a newer close.
    closes: u64,
    /// The newest membership of each connection and room the client ended
    /// (left, or replaced by a newer one), numbered, and in the order they
    /// ended: an announce naming it or an older one is refused. A membership
    /// dropped because its connection closed or it went silent is not ended:
    /// the client may still be in it, and carry on over a new connection.
    ended: HashMap<(SwarmSession, RoomKey), Ended>,
    /// When each was noted, oldest first; an entry whose number is no longer
    /// its membership's is stale and skipped.
    ended_order: VecDeque<((SwarmSession, RoomKey), u64, Instant)>,
    ends: u64,
    /// Each connection's and each host's ended memberships, oldest first.
    ended_by_session: HashMap<SwarmSession, VecDeque<RoomKey>>,
    ended_by_host: HashMap<IpAddr, VecDeque<(SwarmSession, RoomKey)>>,
    members: usize,
    /// Members from each host, see [`MAX_MEMBERS_PER_HOST`].
    by_host: HashMap<IpAddr, usize>,
    stored_sdp_bytes: usize,
    /// Stored SDP bytes by the host that sent them.
    sdp_by_host: HashMap<IpAddr, usize>,
    pending_offers: usize,
}

/// The node's swarm rendezvous.
#[derive(Default)]
pub struct SwarmService {
    state: Mutex<State>,
    waiting: AtomicUsize,
    counters: SwarmCounters,
    /// This node's STUN servers, as handed to members.
    ice_servers: RwLock<Vec<String>>,
    /// Hosts (IPv4 addresses, IPv6 /64s) that announced recently: the only
    /// ones the node's STUN responder answers. A client reaches this list
    /// only over a connection it proved (QUIC, or DTLS and the PQ handshake),
    /// so a spoofed source cannot turn the responder on a third party.
    announcers: RwLock<HashMap<IpAddr, Instant>>,
    /// Native clients' recent requests: a signed request sent again is
    /// refused.
    histories: Mutex<Histories>,
    /// This node's peer id: requests naming another node are refused, so a
    /// signed request this node saw cannot be replayed at another, nor one
    /// another node saw here. Until it is known, every request is refused.
    node_id: RwLock<Option<NodeId>>,
}

impl std::fmt::Debug for SwarmService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SwarmService")
            .field("stats", &self.stats())
            .finish()
    }
}

/// Swarm requests handled at once on the native path. Above
/// [`MAX_WAITING`] so announces that cannot wait still get through.
pub const MAX_SWARM_TASKS: usize = MAX_WAITING + 256;

// The wire discriminants of the swarm requests in `ChunkMessageBody`
// (ant-protocol pins them in a test).
const ANNOUNCE_REQUEST: u64 = 14;
const ANSWER_REQUEST: u64 = 16;
const LEAVE_REQUEST: u64 = 18;

/// Whether an encoded `ChunkMessage` is a swarm request, read from its
/// header alone so the message is not decoded twice: a postcard varint
/// request id, then the body's varint discriminant.
#[must_use]
pub fn is_swarm_request_bytes(data: &[u8]) -> bool {
    let mut bytes = data.iter().copied();
    let mut read_varint = || -> Option<u64> {
        let mut value = 0u64;
        for shift in (0..70).step_by(7) {
            let byte = bytes.next()?;
            value |= u64::from(byte & 0x7f).checked_shl(shift)?;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    };
    let request_id = read_varint();
    let discriminant = read_varint();
    request_id.is_some()
        && matches!(
            discriminant,
            Some(ANNOUNCE_REQUEST | ANSWER_REQUEST | LEAVE_REQUEST)
        )
}

/// An SDP from a member, as this node passes it on: its candidates may name
/// the member's own host, as this node reaches it, and no other public
/// address, at most `MAX_SWARM_CANDIDATES` of them. Local addresses and mDNS
/// names stay only for a member this node reaches at a local address itself
/// (a network of its own, such as a test network): elsewhere they would let a
/// stranger point readers at their own home networks. The member an SDP goes
/// to sends connectivity checks to each candidate before anything proves who
/// made it.
fn relayable_sdp(sdp: &str, host: Option<IpAddr>) -> String {
    let local = host.is_some_and(|host| !is_global_ip(host));
    constrain_swarm_sdp(sdp, |ip| match ip {
        Some(ip) if is_global_ip(ip) => Some(host_of(ip)) == host,
        _ => local,
    })
}

/// The host `ip` counts as: an IPv4 address, or an IPv6 /64, which one
/// client is usually given whole.
fn host_of(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            if let Some(interface) = octets.get_mut(8..) {
                interface.fill(0);
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        v4 @ IpAddr::V4(_) => v4,
    }
}

fn other_node() -> ProtocolError {
    ProtocolError::Internal("this swarm request is for another node".into())
}

/// Whether a native client's request `body` may start its request history
/// (see [`SwarmService::first_sight`]): an announce, or a leave, which may
/// overtake the announce it ends.
#[must_use]
pub fn starts_history(body: &ChunkMessageBody) -> bool {
    matches!(
        body,
        ChunkMessageBody::SwarmAnnounceRequest(_) | ChunkMessageBody::SwarmLeaveRequest(_)
    )
}

/// Whether a message body is one this service answers.
#[must_use]
pub fn is_swarm_request(body: &ChunkMessageBody) -> bool {
    matches!(
        body,
        ChunkMessageBody::SwarmAnnounceRequest(_)
            | ChunkMessageBody::SwarmAnswerRequest(_)
            | ChunkMessageBody::SwarmLeaveRequest(_)
    )
}

impl State {
    /// Remembers a native client's close, forgetting closes past
    /// [`CLOSED_SESSION_TTL`] and, past [`MAX_CLOSED_SESSIONS`] in the queue,
    /// the oldest; the newest is always kept.
    fn note_close(&mut self, session: SwarmSession, now: Instant) {
        self.closes = self.closes.wrapping_add(1);
        let close = Closed {
            at: now,
            number: self.closes,
        };
        self.closed.insert(session, close);
        self.closed_order.push_back((session, close));
        self.forget_closes(now);
    }

    fn forget_closes(&mut self, now: Instant) {
        while let Some((session, close)) = self.closed_order.front().copied() {
            let expired = now.saturating_duration_since(close.at) >= CLOSED_SESSION_TTL;
            if !expired && self.closed_order.len() <= MAX_CLOSED_SESSIONS {
                break;
            }
            self.closed_order.pop_front();
            // A later close of the same session keeps its own entry.
            if self.closed.get(&session).map(|kept| kept.number) == Some(close.number) {
                self.closed.remove(&session);
            }
        }
    }

    /// Whether `session`'s connection closed since `received`.
    fn closed_since(&self, session: SwarmSession, received: Instant) -> bool {
        self.closed
            .get(&session)
            .is_some_and(|closed| closed.at >= received)
    }

    /// Whether a request of `session` received at `received` must not act:
    /// its connection closed since, it is older than any close is
    /// remembered, or (a browser's) its connection is closing.
    fn stale(
        &self,
        session: SwarmSession,
        received: Instant,
        closing: &CancellationToken,
        now: Instant,
    ) -> bool {
        closing.is_cancelled()
            || now.saturating_duration_since(received) >= CLOSED_SESSION_TTL
            || self.closed_since(session, received)
    }

    /// Remembers that `membership` of `session` (from `host`) in `room_key`
    /// ended, unless a newer one of theirs already did. A connection's place
    /// in a room counts once however often it ends a newer membership there;
    /// past its own share, or its host's, the oldest of its own (or its
    /// host's) goes, so the newest ends are the ones kept.
    fn note_ended(
        &mut self,
        session: SwarmSession,
        host: Option<IpAddr>,
        room_key: RoomKey,
        membership: Membership,
        now: Instant,
    ) {
        let key = (session, room_key);
        let number = self.ends.wrapping_add(1);
        // A newer end of the same place counts as the newest: it goes to the
        // back of every queue, under the host it came from now.
        if let Some(kept) = self.ended.get(&key) {
            if kept.membership >= membership {
                return;
            }
            self.remove_ended(&key);
        }
        {
            let oldest_of_session = self
                .ended_by_session
                .get(&session)
                .filter(|ended| ended.len() >= MAX_ENDED_PER_SESSION)
                .and_then(|ended| ended.front().copied());
            if let Some(room) = oldest_of_session {
                self.remove_ended(&(session, room));
            }
            let oldest_of_host = host
                .and_then(|host| self.ended_by_host.get(&host))
                .filter(|ended| ended.len() >= MAX_ENDED_PER_HOST)
                .and_then(|ended| ended.front().copied());
            if let Some(oldest) = oldest_of_host {
                self.remove_ended(&oldest);
            }
            while self.ended.len() >= MAX_ENDED_MEMBERSHIPS && self.forget_oldest_ended() {}
            self.ended.insert(
                key,
                Ended {
                    membership,
                    number,
                    host,
                },
            );
            self.ended_by_session
                .entry(session)
                .or_default()
                .push_back(room_key);
            if let Some(host) = host {
                self.ended_by_host.entry(host).or_default().push_back(key);
            }
        }
        self.ends = number;
        self.ended_order.push_back((key, number, now));
        self.forget_ended(now);
    }

    fn remove_ended(&mut self, key: &(SwarmSession, RoomKey)) {
        let Some(ended) = self.ended.remove(key) else {
            return;
        };
        let (session, room) = *key;
        if let Some(rooms) = self.ended_by_session.get_mut(&session) {
            rooms.retain(|kept| *kept != room);
            if rooms.is_empty() {
                self.ended_by_session.remove(&session);
            }
        }
        if let Some(host) = ended.host {
            if let Some(keys) = self.ended_by_host.get_mut(&host) {
                keys.retain(|kept| kept != key);
                if keys.is_empty() {
                    self.ended_by_host.remove(&host);
                }
            }
        }
    }

    /// Whether the queue entry `(key, number)` is its membership's newest.
    fn ended_live(&self, key: &(SwarmSession, RoomKey), number: u64) -> bool {
        self.ended.get(key).map(|ended| ended.number) == Some(number)
    }

    /// Forgets the oldest ended membership; `false` if there is none.
    fn forget_oldest_ended(&mut self) -> bool {
        while let Some((key, number, _)) = self.ended_order.pop_front() {
            if self.ended_live(&key, number) {
                self.remove_ended(&key);
                return true;
            }
        }
        false
    }

    /// Forgets ended memberships past [`ENDED_MEMBERSHIP_TTL`], and drops
    /// stale queue entries, so the queue stays near the memberships' number.
    fn forget_ended(&mut self, now: Instant) {
        while let Some((key, number, at)) = self.ended_order.front().copied() {
            let live = self.ended_live(&key, number);
            if live && now.saturating_duration_since(at) < ENDED_MEMBERSHIP_TTL {
                break;
            }
            self.ended_order.pop_front();
            if live {
                self.remove_ended(&key);
            }
        }
        if self.ended_order.len() > 2 * self.ended.len() + 1024 {
            let ended = &self.ended;
            self.ended_order
                .retain(|(key, number, _)| ended.get(key).map(|kept| kept.number) == Some(*number));
        }
    }

    /// Whether `membership` of `session` in `room_key`, or a newer one of
    /// theirs, ended.
    fn ended_covers(
        &self,
        session: SwarmSession,
        room_key: &RoomKey,
        membership: Membership,
    ) -> bool {
        self.ended
            .get(&(session, *room_key))
            .is_some_and(|ended| ended.membership >= membership)
    }

    /// Takes `bytes` of the stored-SDP budget, and of `host`'s share of it,
    /// if both fit.
    fn reserve(&mut self, bytes: usize, host: Option<IpAddr>) -> bool {
        let Some(total) = self
            .stored_sdp_bytes
            .checked_add(bytes)
            .filter(|total| *total <= MAX_STORED_SDP_BYTES)
        else {
            return false;
        };
        if let Some(host) = host {
            let held = self.sdp_by_host.get(&host).copied().unwrap_or(0);
            let Some(share) = held
                .checked_add(bytes)
                .filter(|share| *share <= MAX_STORED_SDP_BYTES_PER_HOST)
            else {
                return false;
            };
            self.sdp_by_host.insert(host, share);
        }
        self.stored_sdp_bytes = total;
        true
    }

    fn release(&mut self, bytes: usize, host: Option<IpAddr>) {
        self.stored_sdp_bytes = self.stored_sdp_bytes.saturating_sub(bytes);
        if let Some(host) = host {
            if let Some(share) = self.sdp_by_host.get_mut(&host) {
                *share = share.saturating_sub(bytes);
                if *share == 0 {
                    self.sdp_by_host.remove(&host);
                }
            }
        }
    }

    fn release_all(&mut self, freed: Vec<(usize, Option<IpAddr>)>) {
        for (bytes, host) in freed {
            self.release(bytes, host);
        }
    }

    /// Forgets a member and everything it held, and every signal of its
    /// still queued for others and every offer made to it: none can be
    /// answered now, so none keeps an inbox place or the budget.
    fn drop_member(&mut self, room_key: &RoomKey, member_id: &MemberId) {
        let Some(room) = self.rooms.get_mut(room_key) else {
            return;
        };
        let Some(member) = room.members.remove(member_id) else {
            return;
        };
        room.by_session.remove(&member.session);
        let mut freed: Vec<(usize, Option<IpAddr>)> = member
            .inbox
            .iter()
            .map(|queued| (queued.bytes, queued.host))
            .collect();
        let mut pending = member.pending.len();
        for other in room.members.values_mut() {
            other.inbox.retain(|queued| {
                let (SwarmSignal::Offer { from, .. } | SwarmSignal::Answer { from, .. }) =
                    &queued.signal;
                let keep = from != member_id;
                if !keep {
                    freed.push((queued.bytes, queued.host));
                }
                keep
            });
            let before = other.pending.len();
            other.pending.retain(|offer| offer.to != *member_id);
            pending += before - other.pending.len();
        }
        let empty = room.members.is_empty();
        if empty {
            self.rooms.remove(room_key);
        }
        if let Some(rooms) = self.sessions.get_mut(&member.session) {
            rooms.retain(|room| room != room_key);
            if rooms.is_empty() {
                self.sessions.remove(&member.session);
            }
        }
        self.release_all(freed);
        self.pending_offers = self.pending_offers.saturating_sub(pending);
        self.members = self.members.saturating_sub(1);
        if let Some(host) = member.host {
            if let Some(count) = self.by_host.get_mut(&host) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.by_host.remove(&host);
                }
            }
        }
        // Waiting announces for this member end now rather than at their deadline.
        member.wake.notify_waiters();
    }
}

impl SwarmService {
    /// A service with no rooms.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Counters for metrics.
    pub fn counters(&self) -> &SwarmCounters {
        &self.counters
    }

    /// Whether a reply to a request of `session` received at `received`
    /// should be dropped: the connection closed since, so sending it would
    /// only make the node dial a client that left.
    pub fn reply_unwanted(&self, session: SwarmSession, received: Instant) -> bool {
        self.state.lock().closed_since(session, received)
    }

    /// Sets this node's peer id, which every request it answers must name.
    pub fn set_node_id(&self, node_id: NodeId) {
        *self.node_id.write() = Some(node_id);
    }

    /// Sets the STUN servers handed to members (this node's own, once its
    /// public address is known).
    pub fn set_ice_servers(&self, servers: Vec<String>) {
        *self.ice_servers.write() = servers
            .into_iter()
            .filter(|server| server.len() <= MAX_SWARM_ICE_SERVER_BYTES)
            .take(MAX_SWARM_ICE_SERVERS)
            .collect();
    }

    /// Whether the STUN responder should answer `ip`: it announced in a room
    /// within [`MEMBER_TTL`].
    pub fn stun_allows(&self, ip: IpAddr, now: Instant) -> bool {
        self.announcers
            .read()
            .get(&host_of(ip))
            .is_some_and(|seen| now.saturating_duration_since(*seen) < MEMBER_TTL)
    }

    /// Takes a place among the waiting announces, if there is one.
    fn admit_waiter(&self) -> bool {
        let mut waiting = self.waiting.load(Ordering::Acquire);
        loop {
            if waiting >= MAX_WAITING {
                return false;
            }
            match self.waiting.compare_exchange_weak(
                waiting,
                waiting + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => waiting = actual,
            }
        }
    }

    fn note_announcer(&self, ip: IpAddr, now: Instant) {
        // By host (an IPv4 address, or an IPv6 /64, as the STUN responder's
        // own limits count), so one host cannot fill the list by announcing
        // from address after address of its own.
        let ip = host_of(ip);
        // Most announces refresh a known address: a read lock does, so the
        // STUN responder's lookups on the packet path rarely wait.
        if let Some(seen) = self.announcers.read().get(&ip) {
            if now.saturating_duration_since(*seen) < MEMBER_TTL / 2 {
                return;
            }
        }
        let mut announcers = self.announcers.write();
        if !announcers.contains_key(&ip) && announcers.len() >= MAX_STUN_SOURCES {
            announcers.retain(|_, seen| now.saturating_duration_since(*seen) < MEMBER_TTL);
            if announcers.len() >= MAX_STUN_SOURCES {
                return;
            }
        }
        announcers.insert(ip, now);
    }

    /// Whether a native client's signed swarm request, from `source_ip`, is
    /// new: signed within [`MAX_REQUEST_SKEW`] of `now_unix`, not more than a
    /// few seconds older than the client's newest, and not seen before. A
    /// signed request is authentic but not bound to the connection it came
    /// on, so a node that saw it could send it again in the client's name.
    /// Only an announce or a leave (`starts`) makes a client's history: an
    /// answer comes from a member, which announced first, while a leave may
    /// overtake the announce it ends.
    pub fn first_sight(
        &self,
        peer: [u8; 32],
        source_ip: Option<IpAddr>,
        request_id: u64,
        signed_at: u64,
        now_unix: u64,
        starts: bool,
    ) -> bool {
        let skew = MAX_REQUEST_SKEW.as_secs();
        if signed_at.saturating_add(skew) < now_unix || signed_at > now_unix.saturating_add(skew) {
            return false;
        }
        let mut histories = self.histories.lock();
        if !histories.by_peer.contains_key(&peer)
            && (!starts || !histories.start(peer, source_ip.map(host_of)))
        {
            return false;
        }
        histories
            .by_peer
            .get_mut(&peer)
            .is_some_and(|history| history.note(request_id, signed_at))
    }

    /// Counts for metrics.
    pub fn stats(&self) -> SwarmStats {
        let state = self.state.lock();
        SwarmStats {
            rooms: state.rooms.len(),
            members: state.members,
            pending_offers: state.pending_offers,
            stored_sdp_bytes: state.stored_sdp_bytes,
            waiting: self.waiting.load(Ordering::Relaxed),
        }
    }

    /// Whether swarm request `body` names this node. A native client's request
    /// for another node is answered with an error and leaves its history
    /// alone: a node that saw a client's request could otherwise send it on
    /// here to make the client's later requests here look stale.
    pub fn names_this_node(&self, body: &ChunkMessageBody) -> bool {
        let node = match body {
            ChunkMessageBody::SwarmAnnounceRequest(request) => &request.node,
            ChunkMessageBody::SwarmAnswerRequest(request) => &request.node,
            ChunkMessageBody::SwarmLeaveRequest(request) => &request.node,
            _ => return false,
        };
        self.node_id.read().as_ref() == Some(node)
    }

    /// Answers one swarm request from `session`, which arrived from
    /// `source_ip` at `received`, or returns `None` if `body` is not a swarm
    /// request. A native client's announce may wait for a signal; it ends at
    /// its deadline, on the first signal, when its member is dropped, or when
    /// `shutdown` is cancelled. A request received before its connection
    /// closed (or, for a browser, whose `shutdown` is cancelled) joins nothing.
    pub async fn handle(
        &self,
        session: SwarmSession,
        source_ip: Option<IpAddr>,
        body: ChunkMessageBody,
        shutdown: &CancellationToken,
        received: Instant,
    ) -> Option<ChunkMessageBody> {
        let for_this_node = |node: &NodeId| self.node_id.read().as_ref() == Some(node);
        match body {
            ChunkMessageBody::SwarmAnnounceRequest(request) => {
                if !for_this_node(&request.node) {
                    return Some(ChunkMessageBody::SwarmAnnounceResponse(
                        SwarmAnnounceResponse::Error(other_node()),
                    ));
                }
                Some(ChunkMessageBody::SwarmAnnounceResponse(
                    self.announce(session, source_ip, request, shutdown, received)
                        .await,
                ))
            }
            ChunkMessageBody::SwarmAnswerRequest(request) => {
                if !for_this_node(&request.node) {
                    return Some(ChunkMessageBody::SwarmAnswerResponse(
                        SwarmAnswerResponse::Error(other_node()),
                    ));
                }
                Some(ChunkMessageBody::SwarmAnswerResponse(self.answer(
                    session,
                    source_ip.map(host_of),
                    &request,
                    received,
                    shutdown,
                )))
            }
            ChunkMessageBody::SwarmLeaveRequest(request) => {
                if !for_this_node(&request.node) {
                    return Some(ChunkMessageBody::SwarmLeaveResponse(
                        SwarmLeaveResponse::Error(other_node()),
                    ));
                }
                Some(ChunkMessageBody::SwarmLeaveResponse(
                    self.leave(session, source_ip, &request, received, shutdown),
                ))
            }
            _ => None,
        }
    }

    async fn announce(
        &self,
        session: SwarmSession,
        source_ip: Option<IpAddr>,
        request: SwarmAnnounceRequest,
        shutdown: &CancellationToken,
        received: Instant,
    ) -> SwarmAnnounceResponse {
        self.counters.announces.fetch_add(1, Ordering::Relaxed);
        if let Err(error) = request.validate() {
            return SwarmAnnounceResponse::Error(error);
        }
        // A node browsers cannot reach (no WebRTC Direct endpoint, so no STUN
        // server to name either) is no meeting place: native readers that met
        // here would never meet the browsers, which look only for nodes they
        // can reach, and would get no STUN from it. Refusing sends every
        // client on to the closest nodes that have both, at once.
        if self.ice_servers.read().is_empty() {
            self.counters.refused.fetch_add(1, Ordering::Relaxed);
            return SwarmAnnounceResponse::Refused(SwarmRefusal::NotHosting);
        }
        let mut request = request;
        let host = source_ip.map(host_of);
        for offer in &mut request.offers {
            offer.sdp = relayable_sdp(&offer.sdp, host);
        }
        let now = Instant::now();
        let room = request.room;
        // A browser's waiting request would hold one of its session's few
        // request slots, and its byte reservation, at this node, delaying its
        // reads: a browser never waits, and asks again instead.
        let wait = match session {
            SwarmSession::Browser(_) => Duration::ZERO,
            SwarmSession::Native(_) => Duration::from_millis(u64::from(request.wait_ms)),
        };
        let joined = match self.join_and_offer(session, source_ip, request, now, received, shutdown)
        {
            Ok(joined) => joined,
            Err(refusal) => {
                self.counters.refused.fetch_add(1, Ordering::Relaxed);
                return SwarmAnnounceResponse::Refused(refusal);
            }
        };
        if let Some(ip) = source_ip {
            self.note_announcer(ip, now);
        }

        // Nothing waiting yet: hold the reply until a signal comes, the
        // deadline passes, the member is dropped, or the node stops. One
        // announce per member waits; no lock is held meanwhile.
        if !wait.is_zero() {
            if let Some(_turn) = self.wait_turn(&room, &joined.member) {
                let deadline = tokio::time::Instant::now() + wait;
                loop {
                    // Registered before the inbox is looked at, so a signal
                    // that arrives in between still wakes it.
                    let notified = joined.wake.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    if self.inbox_waits(&room, &joined.member) != Some(true) {
                        break;
                    }
                    tokio::select! {
                        () = &mut notified => {}
                        () = tokio::time::sleep_until(deadline) => break,
                        () = shutdown.cancelled() => break,
                    }
                }
            }
        }

        let mut state = self.state.lock();
        // A member replaced or dropped while the announce waited is not
        // reported as joined.
        let current = state
            .rooms
            .get(&room)
            .and_then(|kept| kept.by_session.get(&session))
            == Some(&joined.member);
        let drained =
            current.then(|| Self::drain(&mut state, &room, &joined.member, Instant::now()));
        drop(state);
        let Some((members, inbox)) = drained else {
            return SwarmAnnounceResponse::Refused(SwarmRefusal::Superseded);
        };
        SwarmAnnounceResponse::Joined {
            member: joined.member,
            members,
            offers_delivered: joined.offers_delivered,
            inbox,
            ice_servers: self.ice_servers.read().clone(),
        }
    }

    /// Whether the member is still there with nothing for it yet (`None` if
    /// it was dropped).
    fn inbox_waits(&self, room_key: &RoomKey, member_id: &MemberId) -> Option<bool> {
        self.state
            .lock()
            .rooms
            .get(room_key)
            .and_then(|room| room.members.get(member_id))
            .map(|member| member.inbox.is_empty())
    }

    /// A place among the waiting announces for this member, unless one of
    /// its announces waits already or every place is taken.
    fn wait_turn<'a>(&'a self, room_key: &RoomKey, member_id: &MemberId) -> Option<WaitTurn<'a>> {
        if !Self::claim_wait(&mut self.state.lock(), room_key, member_id, || {
            self.admit_waiter()
        }) {
            return None;
        }
        Some(WaitTurn {
            service: self,
            room: *room_key,
            member: *member_id,
        })
    }

    /// Marks the member as waiting, if none of its announces is and `admit`
    /// gives a place.
    fn claim_wait(
        state: &mut State,
        room_key: &RoomKey,
        member_id: &MemberId,
        admit: impl FnOnce() -> bool,
    ) -> bool {
        let Some(member) = state
            .rooms
            .get_mut(room_key)
            .and_then(|room| room.members.get_mut(member_id))
        else {
            return false;
        };
        if member.waiting || !admit() {
            return false;
        }
        member.waiting = true;
        true
    }

    /// Joins (or refreshes) `session` in the room, and hands each offer to a
    /// different member picked at random.
    fn join_and_offer(
        &self,
        session: SwarmSession,
        source_ip: Option<IpAddr>,
        request: SwarmAnnounceRequest,
        now: Instant,
        received: Instant,
        shutdown: &CancellationToken,
    ) -> Result<Joined, SwarmRefusal> {
        let room_key = request.room;
        let mut state = self.state.lock();
        // Under the lock that closing takes too: either the close comes after
        // and removes this membership, or it came before and is seen here.
        if state.stale(session, received, shutdown, now) {
            return Err(SwarmRefusal::Busy);
        }
        let member_id = Self::admit_member(
            &mut state,
            session,
            source_ip,
            room_key,
            request.membership,
            now,
        )?;
        let wake = Self::refresh_member(&mut state, &room_key, &member_id, now)
            .ok_or(SwarmRefusal::Busy)?;
        let offers_delivered = self.deliver_offers(&mut state, &room_key, member_id, request, now);
        drop(state);
        Ok(Joined {
            member: member_id,
            offers_delivered,
            wake,
        })
    }

    /// The member `session` already is in the room for `membership`, or a
    /// new one if the caps allow. A newer membership takes the place of the
    /// member there; an older one is refused, as the client has left it.
    fn admit_member(
        state: &mut State,
        session: SwarmSession,
        source_ip: Option<IpAddr>,
        room_key: RoomKey,
        membership: Membership,
        now: Instant,
    ) -> Result<MemberId, SwarmRefusal> {
        let current = state.rooms.get(&room_key).and_then(|room| {
            let id = room.by_session.get(&session).copied()?;
            room.members.get(&id).map(|member| (id, member.membership))
        });
        if let Some((id, kept)) = current {
            match membership.cmp(&kept) {
                std::cmp::Ordering::Equal => {
                    // The same membership over another connection (a native
                    // client's address changed) counts against its new host.
                    Self::rehost_member(state, &room_key, &id, source_ip.map(host_of))?;
                    return Ok(id);
                }
                std::cmp::Ordering::Less => return Err(SwarmRefusal::Superseded),
                std::cmp::Ordering::Greater => {
                    state.note_ended(session, source_ip.map(host_of), room_key, kept, now);
                    state.drop_member(&room_key, &id);
                }
            }
        }
        // A membership that ended (or an older one) does not come back, however
        // late its announce arrives.
        if state.ended_covers(session, &room_key, membership) {
            return Err(SwarmRefusal::Superseded);
        }
        if !state.rooms.contains_key(&room_key) && state.rooms.len() >= MAX_ROOMS {
            return Err(SwarmRefusal::TooManyRooms);
        }
        let room_full = state
            .rooms
            .get(&room_key)
            .is_some_and(|room| room.members.len() >= MAX_MEMBERS_PER_ROOM);
        if room_full || state.members >= MAX_MEMBERS {
            return Err(SwarmRefusal::RoomFull);
        }
        let host = source_ip.map(host_of);
        let host_full = host.is_some_and(|host| {
            state.by_host.get(&host).copied().unwrap_or(0) >= MAX_MEMBERS_PER_HOST
        });
        if host_full || state.sessions.get(&session).map_or(0, Vec::len) >= MAX_ROOMS_PER_SESSION {
            return Err(SwarmRefusal::TooManyRoomsForPeer);
        }
        // Every older membership of the client's here is replaced by this
        // one: none comes back, even after this one goes silent.
        if let Some(older) = membership.checked_sub(1) {
            state.note_ended(session, host, room_key, older, now);
        }
        let member_id: MemberId = rand::random();
        let room = state.rooms.entry(room_key).or_default();
        room.by_session.insert(session, member_id);
        room.members.insert(
            member_id,
            Member {
                session,
                membership,
                host,
                last_seen: now,
                inbox: VecDeque::new(),
                pending: VecDeque::new(),
                wake: Arc::new(Notify::new()),
                waiting: false,
            },
        );
        state.sessions.entry(session).or_default().push(room_key);
        state.members += 1;
        if let Some(host) = host {
            *state.by_host.entry(host).or_default() += 1;
        }
        Ok(member_id)
    }

    /// Counts member `id` against `host` from now on, if it moved there and
    /// that host has room for one more member; its signals already held stay
    /// counted where they were taken.
    fn rehost_member(
        state: &mut State,
        room_key: &RoomKey,
        id: &MemberId,
        host: Option<IpAddr>,
    ) -> Result<(), SwarmRefusal> {
        let Some(old) = state
            .rooms
            .get(room_key)
            .and_then(|room| room.members.get(id))
            .map(|member| member.host)
        else {
            return Ok(());
        };
        if old == host {
            return Ok(());
        }
        if host.is_some_and(|host| {
            state.by_host.get(&host).copied().unwrap_or(0) >= MAX_MEMBERS_PER_HOST
        }) {
            return Err(SwarmRefusal::TooManyRoomsForPeer);
        }
        if let Some(old) = old {
            if let Some(count) = state.by_host.get_mut(&old) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    state.by_host.remove(&old);
                }
            }
        }
        if let Some(host) = host {
            *state.by_host.entry(host).or_default() += 1;
        }
        if let Some(member) = state
            .rooms
            .get_mut(room_key)
            .and_then(|room| room.members.get_mut(id))
        {
            member.host = host;
        }
        Ok(())
    }

    /// Marks the member as seen and forgets its offers nobody answered in
    /// time. Returns its wake-up handle.
    fn refresh_member(
        state: &mut State,
        room_key: &RoomKey,
        member_id: &MemberId,
        now: Instant,
    ) -> Option<Arc<Notify>> {
        let member = state
            .rooms
            .get_mut(room_key)
            .and_then(|room| room.members.get_mut(member_id))?;
        member.last_seen = now;
        let before = member.pending.len();
        member.pending.retain(|pending| pending.expires > now);
        let expired = before - member.pending.len();
        let refreshed = Arc::clone(&member.wake);
        state.pending_offers = state.pending_offers.saturating_sub(expired);
        Some(refreshed)
    }

    /// Hands each offer, in order, to a different other member picked at
    /// random, and returns how many went: always the first ones. A member
    /// whose inbox is full is passed over; the sender's cap on unanswered
    /// offers, or the stored-SDP budget, stops the rest.
    fn deliver_offers(
        &self,
        state: &mut State,
        room_key: &RoomKey,
        sender_id: MemberId,
        request: SwarmAnnounceRequest,
        now: Instant,
    ) -> u32 {
        if request.offers.is_empty() {
            return 0;
        }
        let mut candidates: Vec<MemberId> = state
            .rooms
            .get(room_key)
            .map(|room| {
                room.members
                    .keys()
                    .filter(|other| **other != sender_id)
                    .copied()
                    .collect()
            })
            .unwrap_or_default();
        candidates.shuffle(&mut rand::thread_rng());
        let deadline = now.checked_add(SIGNAL_TTL).unwrap_or(now);
        let total = request.offers.len();
        let mut offers = request.offers.into_iter().peekable();
        let mut delivered = 0u32;
        // Offers go in order, so the client knows which went: the first
        // `delivered`. A recipient with a full inbox is passed over; the
        // sender's pending cap or the SDP budget stops the rest.
        for target in candidates {
            // What the stored SDP holds, which its length alone may not say.
            let Some(bytes) = offers.peek().map(|offer| offer.sdp.capacity()) else {
                break;
            };
            let Some(room) = state.rooms.get(room_key) else {
                break;
            };
            let sender_ok = room
                .members
                .get(&sender_id)
                .is_some_and(|member| member.pending.len() < MAX_PENDING_PER_MEMBER);
            if !sender_ok {
                break;
            }
            let target_ok = room
                .members
                .get(&target)
                .is_some_and(|member| member.inbox.len() < MAX_INBOX_PER_MEMBER);
            if !target_ok {
                continue;
            }
            let host = room.members.get(&sender_id).and_then(|member| member.host);
            if !state.reserve(bytes, host) {
                break;
            }
            let (Some(offer), Some(room)) = (offers.next(), state.rooms.get_mut(room_key)) else {
                state.release(bytes, host);
                break;
            };
            let Some(recipient) = room.members.get_mut(&target) else {
                state.release(bytes, host);
                break;
            };
            recipient.inbox.push_back(Queued {
                signal: SwarmSignal::Offer {
                    from: sender_id,
                    offer_id: offer.offer_id,
                    sdp: offer.sdp,
                },
                bytes,
                host,
                expires: deadline,
            });
            recipient.wake.notify_waiters();
            if let Some(sender) = room.members.get_mut(&sender_id) {
                sender.pending.push_back(Pending {
                    offer_id: offer.offer_id,
                    to: target,
                    expires: deadline,
                });
            }
            state.pending_offers += 1;
            delivered += 1;
        }
        let undelivered = total.saturating_sub(usize::try_from(delivered).unwrap_or(usize::MAX));
        self.counters.offers_undelivered.fetch_add(
            u64::try_from(undelivered).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        self.counters
            .offers_delivered
            .fetch_add(u64::from(delivered), Ordering::Relaxed);
        delivered
    }

    /// Takes the member's signals that fit in one reply, oldest first.
    fn drain(
        state: &mut State,
        room_key: &RoomKey,
        member_id: &MemberId,
        now: Instant,
    ) -> (u32, Vec<SwarmSignal>) {
        let mut signals = Vec::new();
        let mut freed = Vec::new();
        let mut reply_bytes = 0usize;
        let members = state.rooms.get(room_key).map_or(0, |room| {
            u32::try_from(room.members.len()).unwrap_or(u32::MAX)
        });
        if let Some(member) = state
            .rooms
            .get_mut(room_key)
            .and_then(|room| room.members.get_mut(member_id))
        {
            while let Some(front) = member.inbox.front() {
                if front.expires <= now {
                    freed.push((front.bytes, front.host));
                    member.inbox.pop_front();
                    continue;
                }
                let fits = signals.len() < MAX_SWARM_INBOX
                    && reply_bytes + front.bytes <= MAX_SWARM_REPLY_SDP_BYTES;
                // The first signal always goes, so one large SDP cannot wedge the inbox.
                if !fits && !signals.is_empty() {
                    break;
                }
                let Some(queued) = member.inbox.pop_front() else {
                    break;
                };
                reply_bytes += queued.bytes;
                freed.push((queued.bytes, queued.host));
                signals.push(queued.signal);
            }
        }
        state.release_all(freed);
        (members, signals)
    }

    /// `host` is the one this request came from: the answer's candidates are
    /// kept to it, and its bytes counted against it.
    fn answer(
        &self,
        session: SwarmSession,
        host: Option<IpAddr>,
        request: &SwarmAnswerRequest,
        received: Instant,
        closing: &CancellationToken,
    ) -> SwarmAnswerResponse {
        self.counters.answers.fetch_add(1, Ordering::Relaxed);
        if let Err(error) = request.validate() {
            return SwarmAnswerResponse::Error(error);
        }
        let now = Instant::now();
        let delivered = {
            let mut state = self.state.lock();
            !state.stale(session, received, closing, now)
                && Self::relay_answer(&mut state, session, host, request, now)
        };
        let counter = if delivered {
            &self.counters.answers_delivered
        } else {
            &self.counters.answers_unmatched
        };
        counter.fetch_add(1, Ordering::Relaxed);
        if delivered {
            SwarmAnswerResponse::Delivered
        } else {
            SwarmAnswerResponse::Unmatched
        }
    }

    /// Queues the answer for the member that made the offer, if that member
    /// delivered the offer to this one and it has not expired or been
    /// answered. The offer is consumed whether or not the answer can be kept.
    fn relay_answer(
        state: &mut State,
        session: SwarmSession,
        host: Option<IpAddr>,
        request: &SwarmAnswerRequest,
        now: Instant,
    ) -> bool {
        let Some(answerer) = state
            .rooms
            .get(&request.room)
            .and_then(|room| room.by_session.get(&session).copied())
        else {
            return false;
        };
        let Some(offerer) = state
            .rooms
            .get_mut(&request.room)
            .and_then(|room| room.members.get_mut(&request.to))
        else {
            return false;
        };
        let Some(position) = offerer.pending.iter().position(|pending| {
            pending.offer_id == request.offer_id && pending.to == answerer && pending.expires > now
        }) else {
            return false;
        };
        offerer.pending.remove(position);
        let has_room = offerer.inbox.len() < MAX_INBOX_PER_MEMBER;
        state.pending_offers = state.pending_offers.saturating_sub(1);
        let sdp = relayable_sdp(&request.sdp, host);
        let bytes = sdp.capacity();
        if !has_room || !state.reserve(bytes, host) {
            return false;
        }
        let Some(offerer) = state
            .rooms
            .get_mut(&request.room)
            .and_then(|room| room.members.get_mut(&request.to))
        else {
            state.release(bytes, host);
            return false;
        };
        offerer.inbox.push_back(Queued {
            signal: SwarmSignal::Answer {
                from: answerer,
                offer_id: request.offer_id,
                sdp,
            },
            bytes,
            host,
            expires: now.checked_add(SIGNAL_TTL).unwrap_or(now),
        });
        offerer.wake.notify_waiters();
        true
    }

    fn leave(
        &self,
        session: SwarmSession,
        source_ip: Option<IpAddr>,
        request: &SwarmLeaveRequest,
        received: Instant,
        closing: &CancellationToken,
    ) -> SwarmLeaveResponse {
        let mut state = self.state.lock();
        // A leave from before a close would remove a later connection's
        // membership; the close already removed its own.
        if state.stale(session, received, closing, Instant::now()) {
            return SwarmLeaveResponse::Left;
        }
        // The membership the leave names ends, and so does an older one in
        // its place; a newer one stays. It is remembered as ended even if its
        // announce has not arrived yet, so that announce cannot join.
        let now = Instant::now();
        let member = state.rooms.get(&request.room).and_then(|room| {
            let id = room.by_session.get(&session).copied()?;
            room.members
                .get(&id)
                .is_some_and(|member| member.membership <= request.membership)
                .then_some(id)
        });
        if let Some(member) = member {
            state.drop_member(&request.room, &member);
        }
        state.note_ended(
            session,
            source_ip.map(host_of),
            request.room,
            request.membership,
            now,
        );
        SwarmLeaveResponse::Left
    }

    /// Removes every membership of a connection that closed, and remembers
    /// the close a while, so a request of the connection still being handled
    /// cannot join again.
    pub fn session_closed(&self, session: SwarmSession) {
        let mut state = self.state.lock();
        if let SwarmSession::Native(_) = session {
            state.note_close(session, Instant::now());
        }
        let rooms = state.sessions.get(&session).cloned().unwrap_or_default();
        for room_key in rooms {
            let member = state
                .rooms
                .get(&room_key)
                .and_then(|room| room.by_session.get(&session).copied());
            if let Some(member) = member {
                state.drop_member(&room_key, &member);
            }
        }
    }

    /// Drops members that stopped announcing, and signals and offers that
    /// expired.
    pub fn sweep(&self, now: Instant) {
        let mut guard = self.state.lock();
        let state = &mut *guard;
        let mut silent = Vec::new();
        let mut freed = Vec::new();
        let mut expired_offers = 0usize;
        for (room_key, room) in &mut state.rooms {
            for (member_id, member) in &mut room.members {
                if now.saturating_duration_since(member.last_seen) >= MEMBER_TTL {
                    silent.push((*room_key, *member_id));
                    continue;
                }
                member.inbox.retain(|queued| {
                    let keep = queued.expires > now;
                    if !keep {
                        freed.push((queued.bytes, queued.host));
                    }
                    keep
                });
                let before = member.pending.len();
                member.pending.retain(|pending| pending.expires > now);
                expired_offers += before - member.pending.len();
            }
        }
        state.release_all(freed);
        state.pending_offers = state.pending_offers.saturating_sub(expired_offers);
        for (room_key, member_id) in &silent {
            state.drop_member(room_key, member_id);
        }
        state.forget_closes(now);
        state.forget_ended(now);
        drop(guard);
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        self.histories
            .lock()
            .forget_older_than(now_unix.saturating_sub(MAX_REQUEST_SKEW.as_secs()));
        self.announcers
            .write()
            .retain(|_, seen| now.saturating_duration_since(*seen) < MEMBER_TTL);
        if !silent.is_empty() {
            self.counters.members_expired.fetch_add(
                u64::try_from(silent.len()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            debug!(expired = silent.len(), "swarm members expired");
        }
    }
}

struct Joined {
    member: MemberId,
    offers_delivered: u32,
    wake: Arc<Notify>,
}

/// A waiting announce's place, given back however the wait ends.
struct WaitTurn<'a> {
    service: &'a SwarmService,
    room: RoomKey,
    member: MemberId,
}

impl Drop for WaitTurn<'_> {
    fn drop(&mut self) {
        self.service.waiting.fetch_sub(1, Ordering::AcqRel);
        if let Some(member) = self
            .service
            .state
            .lock()
            .rooms
            .get_mut(&self.room)
            .and_then(|room| room.members.get_mut(&self.member))
        {
            member.waiting = false;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ant_protocol::swarm::{SwarmOffer, MAX_SWARM_SDP_BYTES};

    /// The node the tests' requests are for.
    const NODE: NodeId = [0xee; 32];

    /// A node's STUN server, as one with a browser endpoint names it.
    const STUN: &str = "stun:203.0.113.9:10000";

    fn service() -> Arc<SwarmService> {
        let service = SwarmService::new();
        service.set_node_id(NODE);
        service.set_ice_servers(vec![STUN.into()]);
        service
    }

    fn announce(room: u8, offers: &[u8], wait_ms: u32) -> ChunkMessageBody {
        ChunkMessageBody::SwarmAnnounceRequest(SwarmAnnounceRequest {
            room: [room; 32],
            node: NODE,
            membership: 1,
            offers: offers
                .iter()
                .map(|id| SwarmOffer {
                    offer_id: [*id; 16],
                    sdp: format!("v=0 offer {id}"),
                })
                .collect(),
            wait_ms,
        })
    }

    struct Reply {
        member: MemberId,
        members: u32,
        delivered: u32,
        inbox: Vec<SwarmSignal>,
    }

    async fn call(service: &SwarmService, session: SwarmSession, body: ChunkMessageBody) -> Reply {
        let token = CancellationToken::new();
        match service
            .handle(session, None, body, &token, Instant::now())
            .await
        {
            Some(ChunkMessageBody::SwarmAnnounceResponse(SwarmAnnounceResponse::Joined {
                member,
                members,
                offers_delivered,
                inbox,
                ..
            })) => Reply {
                member,
                members,
                delivered: offers_delivered,
                inbox,
            },
            other => panic!("unexpected reply {other:?}"),
        }
    }

    fn answer(room: u8, to: MemberId, offer: u8) -> ChunkMessageBody {
        ChunkMessageBody::SwarmAnswerRequest(SwarmAnswerRequest {
            room: [room; 32],
            node: NODE,
            to,
            offer_id: [offer; 16],
            sdp: "v=0 answer".into(),
        })
    }

    async fn answer_reply(
        service: &SwarmService,
        session: SwarmSession,
        body: ChunkMessageBody,
    ) -> SwarmAnswerResponse {
        match service
            .handle(
                session,
                None,
                body,
                &CancellationToken::new(),
                Instant::now(),
            )
            .await
        {
            Some(ChunkMessageBody::SwarmAnswerResponse(response)) => response,
            other => panic!("unexpected reply {other:?}"),
        }
    }

    const A: SwarmSession = SwarmSession::Browser(1);
    const B: SwarmSession = SwarmSession::Native([2; 32]);
    const C: SwarmSession = SwarmSession::Browser(3);

    #[tokio::test]
    async fn an_offer_reaches_another_member_and_its_answer_comes_back() {
        let service = service();
        let b = call(&service, B, announce(1, &[], 0)).await;
        assert_eq!(b.members, 1);
        let a = call(&service, A, announce(1, &[30, 31], 0)).await;
        assert_eq!((a.members, a.delivered), (2, 1));
        assert_ne!(a.member, b.member);

        let inbox = call(&service, B, announce(1, &[], 0)).await.inbox;
        let [SwarmSignal::Offer { from, offer_id, .. }] = inbox.as_slice() else {
            panic!("expected one offer: {inbox:?}");
        };
        assert_eq!(*from, a.member);
        let offer = offer_id.first().copied().unwrap_or(0);
        assert_eq!(
            answer_reply(&service, B, answer(1, a.member, offer)).await,
            SwarmAnswerResponse::Delivered
        );
        let inbox = call(&service, A, announce(1, &[], 0)).await.inbox;
        assert!(matches!(
            inbox.as_slice(),
            [SwarmSignal::Answer { from, .. }] if *from == b.member
        ));
        // Answered once only.
        assert_eq!(
            answer_reply(&service, B, answer(1, a.member, offer)).await,
            SwarmAnswerResponse::Unmatched
        );
        assert_eq!(service.stats().pending_offers, 0);
        assert_eq!(service.stats().stored_sdp_bytes, 0);
    }

    /// An SDP naming `own` (its sender's public address), a stranger's public
    /// address and a local one.
    fn pointing(own: &str) -> String {
        format!(
            "v=0\r\n\
             a=candidate:1 1 udp 1 {own} 5000 typ srflx raddr 0.0.0.0 rport 0\r\n\
             a=candidate:2 1 udp 1 9.9.9.99 5001 typ host\r\n\
             a=candidate:3 1 udp 1 192.168.1.4 5002 typ host\r\n"
        )
    }

    /// Sends `body` from `session` at `ip`; the inbox and member id of an
    /// announce's reply, if it was one.
    async fn from(
        service: &SwarmService,
        session: SwarmSession,
        ip: &str,
        body: ChunkMessageBody,
    ) -> Option<(MemberId, Vec<SwarmSignal>)> {
        let ip: IpAddr = ip.parse().expect("ip");
        match service
            .handle(
                session,
                Some(ip),
                body,
                &CancellationToken::new(),
                Instant::now(),
            )
            .await
        {
            Some(ChunkMessageBody::SwarmAnnounceResponse(SwarmAnnounceResponse::Joined {
                member,
                inbox,
                ..
            })) => Some((member, inbox)),
            _ => None,
        }
    }

    #[tokio::test]
    async fn a_relayed_sdp_names_no_public_address_but_its_senders() {
        let service = service();
        from(&service, B, "1.1.1.5", announce(1, &[], 0)).await;
        let mut offer = announce(1, &[30], 0);
        if let ChunkMessageBody::SwarmAnnounceRequest(request) = &mut offer {
            for sent in &mut request.offers {
                sent.sdp = pointing("1.1.1.4");
            }
        }
        let (a, _) = from(&service, A, "1.1.1.4", offer).await.expect("joined");
        let (_, inbox) = from(&service, B, "1.1.1.5", announce(1, &[], 0))
            .await
            .expect("joined");
        let [SwarmSignal::Offer { sdp, .. }] = inbox.as_slice() else {
            panic!("expected one offer: {inbox:?}");
        };
        assert!(sdp.contains("1.1.1.4 5000"), "{sdp}");
        // A member reached at a public address keeps no local candidate.
        assert!(!sdp.contains("192.168.1.4"), "{sdp}");
        assert!(!sdp.contains("9.9.9.99"), "{sdp}");

        // The answer, likewise, names its own sender's public address only.
        let mut reply = answer(1, a, 30);
        if let ChunkMessageBody::SwarmAnswerRequest(request) = &mut reply {
            request.sdp = pointing("1.1.1.5");
        }
        from(&service, B, "1.1.1.5", reply).await;
        let (_, inbox) = from(&service, A, "1.1.1.4", announce(1, &[], 0))
            .await
            .expect("joined");
        let [SwarmSignal::Answer { sdp, .. }] = inbox.as_slice() else {
            panic!("expected one answer: {inbox:?}");
        };
        assert!(sdp.contains("1.1.1.5 5000"), "{sdp}");
        assert!(!sdp.contains("9.9.9.99"), "{sdp}");
        // What is held is what goes, and all of it is let go.
        assert_eq!(service.stats().stored_sdp_bytes, 0);
    }

    #[tokio::test]
    async fn a_member_that_moves_counts_and_answers_from_its_new_host() {
        let service = service();
        let (old, new): (IpAddr, IpAddr) = (
            "1.1.1.5".parse().expect("ip"),
            "1.1.1.6".parse().expect("ip"),
        );
        from(&service, B, "1.1.1.5", announce(1, &[], 0)).await;
        // The same membership, over a connection from another address.
        from(&service, B, "1.1.1.6", announce(1, &[], 0)).await;
        {
            let state = service.state.lock();
            assert_eq!(state.by_host.get(&old), None);
            assert_eq!(state.by_host.get(&new), Some(&1));
        }
        let (a, _) = from(&service, A, "1.1.1.4", announce(1, &[30], 0))
            .await
            .expect("joined");
        from(&service, B, "1.1.1.6", announce(1, &[], 0)).await;
        let mut reply = answer(1, a, 30);
        if let ChunkMessageBody::SwarmAnswerRequest(request) = &mut reply {
            request.sdp = pointing("1.1.1.6");
        }
        from(&service, B, "1.1.1.6", reply).await;
        let (_, inbox) = from(&service, A, "1.1.1.4", announce(1, &[], 0))
            .await
            .expect("joined");
        let [SwarmSignal::Answer { sdp, .. }] = inbox.as_slice() else {
            panic!("expected one answer: {inbox:?}");
        };
        // The answer names the address it came from, which is the member's own.
        assert!(sdp.contains("1.1.1.6 5000"), "{sdp}");
    }

    #[tokio::test]
    async fn an_sdp_of_dropped_candidates_is_charged_only_what_it_keeps() {
        let service = service();
        from(&service, B, "1.1.1.5", announce(1, &[], 0)).await;
        let mut offer = announce(1, &[31], 0);
        if let ChunkMessageBody::SwarmAnnounceRequest(request) = &mut offer {
            for sent in &mut request.offers {
                // A stranger's address, spelled as a receiver still reads
                // it, filling the SDP: none of it is passed on.
                sent.sdp = String::from("v=0\r\n");
                while sent.sdp.len() < MAX_SWARM_SDP_BYTES - 64 {
                    sent.sdp
                        .push_str("a= candidate:2 1 udp 1 9.9.9.99 5001 typ host\r\n");
                }
            }
        }
        from(&service, A, "1.1.1.4", offer).await;
        assert_eq!(service.stats().pending_offers, 1);
        let held = service.stats().stored_sdp_bytes;
        assert!(held < 64, "{held} bytes charged for a 5-byte SDP");
        let (_, inbox) = from(&service, B, "1.1.1.5", announce(1, &[], 0))
            .await
            .expect("joined");
        let [SwarmSignal::Offer { sdp, .. }] = inbox.as_slice() else {
            panic!("expected one offer: {inbox:?}");
        };
        assert_eq!(sdp, "v=0\r\n");
    }

    #[test]
    fn a_member_on_this_nodes_own_network_keeps_its_local_candidates() {
        let sdp = format!(
            "{}a=candidate:4 1 udp 1 1f2e3d4c.local 5003 typ host\r\n",
            pointing("10.78.3.2")
        );
        let kept = relayable_sdp(&sdp, Some(host_of("10.78.3.2".parse().expect("ip"))));
        assert!(kept.contains("10.78.3.2 5000"), "{kept}");
        assert!(kept.contains("192.168.1.4 5002"), "{kept}");
        assert!(kept.contains("1f2e3d4c.local"), "{kept}");
        assert!(!kept.contains("9.9.9.99"), "{kept}");
        let public = relayable_sdp(&sdp, Some(host_of("1.1.1.4".parse().expect("ip"))));
        assert!(
            !public.contains(".local") && !public.contains("192.168.1.4"),
            "{public}"
        );
        // A member whose address this node cannot tell keeps nothing local.
        assert!(!relayable_sdp(&sdp, None).contains("192.168.1.4"));
    }

    #[tokio::test]
    async fn answers_nobody_asked_for_go_nowhere() {
        let service = service();
        let a = call(&service, A, announce(1, &[], 0)).await;
        let _b = call(&service, B, announce(1, &[], 0)).await;
        let _c = call(&service, C, announce(2, &[], 0)).await;
        // No offer 9 was delivered to B; C is not in room 1.
        assert_eq!(
            answer_reply(&service, B, answer(1, a.member, 9)).await,
            SwarmAnswerResponse::Unmatched
        );
        assert_eq!(
            answer_reply(&service, C, answer(1, a.member, 9)).await,
            SwarmAnswerResponse::Unmatched
        );
        assert_eq!(call(&service, A, announce(1, &[], 0)).await.inbox, []);
    }

    #[tokio::test]
    async fn a_waiting_announce_wakes_on_the_first_signal() {
        let service = service();
        let _b = call(&service, B, announce(1, &[], 0)).await;
        let waiting = {
            let service = Arc::clone(&service);
            tokio::spawn(async move { call(&service, B, announce(1, &[], 10_000)).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(service.stats().waiting, 1);
        let started = Instant::now();
        let _a = call(&service, A, announce(1, &[40], 0)).await;
        let reply = waiting.await.expect("task");
        assert_eq!(reply.inbox.len(), 1);
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(service.stats().waiting, 0);
    }

    #[tokio::test]
    async fn a_waiting_announce_ends_when_the_node_stops() {
        let service = service();
        let token = CancellationToken::new();
        let waiting = {
            let service = Arc::clone(&service);
            let token = token.clone();
            tokio::spawn(async move {
                service
                    .handle(B, None, announce(1, &[], 20_000), &token, Instant::now())
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        token.cancel();
        let reply = tokio::time::timeout(Duration::from_secs(2), waiting).await;
        assert!(matches!(
            reply,
            Ok(Ok(Some(ChunkMessageBody::SwarmAnnounceResponse(
                SwarmAnnounceResponse::Joined { .. }
            ))))
        ));
    }

    #[tokio::test]
    async fn caps_refuse_newcomers_and_leaving_frees_the_place() {
        let service = service();
        for n in 0..MAX_ROOMS_PER_SESSION {
            let room = u8::try_from(n).unwrap_or(0);
            let _ = call(&service, A, announce(room, &[], 0)).await;
        }
        let refused = service
            .handle(
                A,
                None,
                announce(200, &[], 0),
                &CancellationToken::new(),
                Instant::now(),
            )
            .await;
        assert!(matches!(
            refused,
            Some(ChunkMessageBody::SwarmAnnounceResponse(
                SwarmAnnounceResponse::Refused(SwarmRefusal::TooManyRoomsForPeer)
            ))
        ));
        service.session_closed(A);
        assert_eq!(service.stats(), SwarmStats::default());
        let _ = call(&service, A, announce(200, &[], 0)).await;
        let _ = service
            .handle(
                A,
                None,
                ChunkMessageBody::SwarmLeaveRequest(SwarmLeaveRequest {
                    room: [200; 32],
                    node: NODE,
                    membership: 1,
                }),
                &CancellationToken::new(),
                Instant::now(),
            )
            .await;
        assert_eq!(service.stats().members, 0);
    }

    #[tokio::test]
    async fn unanswered_offers_and_silent_members_expire() {
        let service = service();
        let _b = call(&service, B, announce(1, &[], 0)).await;
        let _a = call(&service, A, announce(1, &[50], 0)).await;
        assert_eq!(service.stats().pending_offers, 1);
        assert!(service.stats().stored_sdp_bytes > 0);
        let later = Instant::now() + SIGNAL_TTL + Duration::from_secs(1);
        service.sweep(later);
        assert_eq!(service.stats().pending_offers, 0);
        assert_eq!(service.stats().stored_sdp_bytes, 0);
        service.sweep(Instant::now() + MEMBER_TTL + Duration::from_secs(1));
        assert_eq!(service.stats(), SwarmStats::default());
    }

    #[tokio::test]
    async fn a_node_browsers_cannot_reach_hosts_no_rooms() {
        let service = SwarmService::new();
        service.set_node_id(NODE);
        let token = CancellationToken::new();
        let refused = service
            .handle(A, None, announce(1, &[], 0), &token, Instant::now())
            .await;
        assert!(matches!(
            refused,
            Some(ChunkMessageBody::SwarmAnnounceResponse(
                SwarmAnnounceResponse::Refused(SwarmRefusal::NotHosting)
            ))
        ));
        assert_eq!(service.stats().members, 0);
        // Once it has a browser endpoint, and so a STUN server to name, it does.
        service.set_ice_servers(vec![STUN.into()]);
        let joined = service
            .handle(A, None, announce(1, &[], 0), &token, Instant::now())
            .await;
        assert!(matches!(
            joined,
            Some(ChunkMessageBody::SwarmAnnounceResponse(
                SwarmAnnounceResponse::Joined { .. }
            ))
        ));
    }

    #[tokio::test]
    async fn stun_answers_only_recent_announcers_and_replies_name_it() {
        let service = service();
        let ip: IpAddr = "198.51.100.4".parse().expect("ip");
        let other: IpAddr = "198.51.100.5".parse().expect("ip");
        let now = Instant::now();
        assert!(!service.stun_allows(ip, now));
        let reply = service
            .handle(
                A,
                Some(ip),
                announce(1, &[], 0),
                &CancellationToken::new(),
                Instant::now(),
            )
            .await;
        assert!(matches!(
            reply,
            Some(ChunkMessageBody::SwarmAnnounceResponse(SwarmAnnounceResponse::Joined { ice_servers, .. }))
                if ice_servers == vec![STUN.to_string()]
        ));
        assert!(service.stun_allows(ip, Instant::now()));
        assert!(!service.stun_allows(other, Instant::now()));
        // An IPv4-mapped form of the same address counts as the same.
        let mapped: IpAddr = "::ffff:198.51.100.4".parse().expect("ip");
        assert!(service.stun_allows(mapped, Instant::now()));
        service.sweep(Instant::now() + MEMBER_TTL + Duration::from_secs(1));
        assert!(!service.stun_allows(ip, Instant::now() + MEMBER_TTL + Duration::from_secs(1)));
    }

    #[test]
    fn swarm_requests_are_told_apart_from_their_header() {
        use ant_protocol::chunk::{ChunkGetRequest, ChunkMessage};
        let encode = |body: ChunkMessageBody, request_id: u64| {
            ChunkMessage { request_id, body }.encode().expect("encode")
        };
        for request_id in [0, 1, 300, u64::MAX] {
            assert!(is_swarm_request_bytes(&encode(
                announce(1, &[1], 0),
                request_id
            )));
            assert!(is_swarm_request_bytes(&encode(
                answer(1, [2; 16], 3),
                request_id
            )));
            assert!(is_swarm_request_bytes(&encode(
                ChunkMessageBody::SwarmLeaveRequest(SwarmLeaveRequest {
                    room: [1; 32],
                    node: NODE,
                    membership: 1,
                }),
                request_id
            )));
            assert!(!is_swarm_request_bytes(&encode(
                ChunkMessageBody::GetRequest(ChunkGetRequest::new([1; 32])),
                request_id
            )));
        }
        assert!(!is_swarm_request_bytes(&[]));
        assert!(!is_swarm_request_bytes(&[0xff; 12]));
    }

    #[tokio::test]
    async fn a_browser_never_waits() {
        let service = service();
        let started = Instant::now();
        let _ = call(&service, A, announce(1, &[], 10_000)).await;
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn a_member_waits_with_one_announce_at_a_time() {
        let service = service();
        let _ = call(&service, B, announce(1, &[], 0)).await;
        let waiting = {
            let service = Arc::clone(&service);
            tokio::spawn(async move { call(&service, B, announce(1, &[], 10_000)).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        let started = Instant::now();
        let _ = call(&service, B, announce(1, &[], 10_000)).await;
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(service.stats().waiting, 1);
        // Closing the connection ends the wait, and frees the place.
        service.session_closed(B);
        let ended = tokio::time::timeout(Duration::from_secs(2), waiting).await;
        assert!(ended.is_ok());
        assert_eq!(service.stats().waiting, 0);
    }

    #[tokio::test]
    async fn a_signal_already_taken_does_not_cut_a_later_wait_short() {
        let service = service();
        let _ = call(&service, B, announce(1, &[], 0)).await;
        // An offer arrives while B is not waiting, and B takes it at once.
        let _ = call(&service, A, announce(1, &[60], 0)).await;
        assert_eq!(call(&service, B, announce(1, &[], 0)).await.inbox.len(), 1);
        let started = Instant::now();
        let reply = call(&service, B, announce(1, &[], 300)).await;
        assert_eq!(reply.inbox, []);
        assert!(started.elapsed() >= Duration::from_millis(250));
    }

    #[tokio::test]
    async fn a_request_from_before_its_connection_closed_joins_nothing() {
        let service = service();
        let before = Instant::now();
        tokio::time::sleep(Duration::from_millis(5)).await;
        service.session_closed(B);
        let late = service
            .handle(
                B,
                None,
                announce(1, &[], 0),
                &CancellationToken::new(),
                before,
            )
            .await;
        assert!(matches!(
            late,
            Some(ChunkMessageBody::SwarmAnnounceResponse(
                SwarmAnnounceResponse::Refused(SwarmRefusal::Busy)
            ))
        ));
        assert_eq!(service.stats().members, 0);
        // A browser whose connection is closing joins nothing either.
        let closing = CancellationToken::new();
        closing.cancel();
        let refused = service
            .handle(A, None, announce(1, &[], 0), &closing, Instant::now())
            .await;
        assert!(matches!(
            refused,
            Some(ChunkMessageBody::SwarmAnnounceResponse(
                SwarmAnnounceResponse::Refused(SwarmRefusal::Busy)
            ))
        ));
        // A request after the close is a new connection's.
        let _ = call(&service, B, announce(1, &[], 0)).await;
        assert_eq!(service.stats().members, 1);
    }

    #[tokio::test]
    async fn a_request_for_another_node_is_refused() {
        let service = service();
        let mut elsewhere = SwarmAnnounceRequest {
            room: [1; 32],
            node: [1; 32],
            membership: 1,
            offers: Vec::new(),
            wait_ms: 0,
        };
        let token = CancellationToken::new();
        let reply = service
            .handle(
                B,
                None,
                ChunkMessageBody::SwarmAnnounceRequest(elsewhere.clone()),
                &token,
                Instant::now(),
            )
            .await;
        assert!(matches!(
            reply,
            Some(ChunkMessageBody::SwarmAnnounceResponse(
                SwarmAnnounceResponse::Error(_)
            ))
        ));
        assert_eq!(service.stats().members, 0);
        // A node that does not know its own id yet answers nothing.
        let unknown = SwarmService::new();
        elsewhere.node = NODE;
        let reply = unknown
            .handle(
                B,
                None,
                ChunkMessageBody::SwarmAnnounceRequest(elsewhere),
                &token,
                Instant::now(),
            )
            .await;
        assert!(matches!(
            reply,
            Some(ChunkMessageBody::SwarmAnnounceResponse(
                SwarmAnnounceResponse::Error(_)
            ))
        ));
        // A leave for another node is told so too, and ends nothing here.
        let _ = call(&service, A, announce(1, &[], 0)).await;
        let leave = service
            .handle(
                A,
                None,
                ChunkMessageBody::SwarmLeaveRequest(SwarmLeaveRequest {
                    room: [1; 32],
                    node: [1; 32],
                    membership: 1,
                }),
                &token,
                Instant::now(),
            )
            .await;
        assert!(matches!(
            leave,
            Some(ChunkMessageBody::SwarmLeaveResponse(
                SwarmLeaveResponse::Error(_)
            ))
        ));
        assert_eq!(service.stats().members, 1);
    }

    #[tokio::test]
    async fn a_leave_from_before_a_close_spares_the_next_connection() {
        let service = service();
        let leave_received = Instant::now();
        tokio::time::sleep(Duration::from_millis(5)).await;
        service.session_closed(B);
        // The same client, connected again, joins.
        let _ = call(&service, B, announce(1, &[], 0)).await;
        let leave = ChunkMessageBody::SwarmLeaveRequest(SwarmLeaveRequest {
            room: [1; 32],
            node: NODE,
            membership: 1,
        });
        let _ = service
            .handle(B, None, leave, &CancellationToken::new(), leave_received)
            .await;
        assert_eq!(service.stats().members, 1);
    }

    #[tokio::test]
    async fn offers_go_in_order_and_the_rest_are_counted() {
        let service = service();
        let _b = call(&service, B, announce(1, &[], 0)).await;
        // Two offers, one other member: the first goes, the second does not.
        let a = call(&service, A, announce(1, &[70, 71], 0)).await;
        assert_eq!(a.delivered, 1);
        let inbox = call(&service, B, announce(1, &[], 0)).await.inbox;
        assert!(matches!(
            inbox.as_slice(),
            [SwarmSignal::Offer { offer_id, .. }] if *offer_id == [70; 16]
        ));
        assert_eq!(
            service
                .counters()
                .offers_undelivered
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn closes_of_one_session_keep_the_queue_bounded() {
        let mut state = State::default();
        let start = Instant::now();
        let session = SwarmSession::Native([7; 32]);
        for _ in 0..(3 * MAX_CLOSED_SESSIONS) {
            state.note_close(session, start);
        }
        assert!(state.closed_order.len() <= MAX_CLOSED_SESSIONS);
        assert!(state.closed_since(session, start));
    }

    #[test]
    fn closes_are_forgotten_in_order_and_the_newest_is_kept() {
        let mut state = State::default();
        let start = Instant::now();
        for n in 0..(MAX_CLOSED_SESSIONS + 10) {
            let mut peer = [0u8; 32];
            peer[..8].copy_from_slice(&(n as u64).to_be_bytes());
            state.note_close(SwarmSession::Native(peer), start);
        }
        assert_eq!(state.closed.len(), MAX_CLOSED_SESSIONS);
        // The newest close is always remembered.
        let newest = SwarmSession::Native([0xff; 32]);
        state.note_close(newest, start);
        assert!(state.closed.contains_key(&newest));
        state.forget_closes(start + CLOSED_SESSION_TTL);
        assert!(state.closed.is_empty() && state.closed_order.is_empty());
    }

    #[test]
    fn a_signed_request_counts_once_and_only_while_fresh() {
        let service = service();
        let now = 1_000_000;
        let skew = MAX_REQUEST_SKEW.as_secs();
        let seen =
            |peer: u8, id: u64, at: u64| service.first_sight([peer; 32], None, id, at, now, true);
        assert!(seen(1, 7, now));
        // The same request again, as a node that saw it might send it.
        assert!(!seen(1, 7, now));
        // Another client's request with the same id is its own.
        assert!(seen(2, 7, now));
        // Too old, or from too far ahead.
        assert!(!seen(1, 8, now - skew - 1));
        assert!(!seen(1, 9, now + skew + 1));
        // Overtaken by a newer request by a few seconds: still fine.
        assert!(seen(1, 10, now + 4));
        assert!(seen(1, 11, now));
        // Much older than the newest: an old request sent again.
        assert!(!seen(1, 12, now - REQUEST_REORDER - 1));
    }

    #[test]
    fn only_an_announce_or_a_leave_starts_a_client_s_history() {
        assert!(starts_history(&announce(1, &[], 0)));
        assert!(starts_history(&ChunkMessageBody::SwarmLeaveRequest(
            SwarmLeaveRequest {
                room: [1; 32],
                node: NODE,
                membership: 1,
            }
        )));
        assert!(!starts_history(&answer(1, [2; 16], 3)));
        let service = service();
        let now = 1_000_000;
        assert!(!service.first_sight([3; 32], None, 1, now, now, false));
        assert!(service.histories.lock().by_peer.is_empty());
        assert!(service.first_sight([3; 32], None, 2, now, now, true));
        assert!(service.first_sight([3; 32], None, 3, now, now, false));
    }

    #[test]
    fn one_host_keeps_only_so_many_histories_and_idle_ones_go() {
        let service = service();
        let now = 1_000_000;
        let host: IpAddr = "198.51.100.4".parse().expect("ip");
        let peer = |n: u32| {
            let mut peer = [0u8; 32];
            peer[..4].copy_from_slice(&n.to_be_bytes());
            peer
        };
        for n in 0..u32::try_from(MAX_HISTORIES_PER_HOST).unwrap_or(u32::MAX) {
            assert!(service.first_sight(peer(n), Some(host), 1, now, now, true));
        }
        assert!(!service.first_sight(peer(100_000), Some(host), 1, now, now, true));
        // Another host is not held back.
        let other: IpAddr = "198.51.100.5".parse().expect("ip");
        assert!(service.first_sight(peer(100_001), Some(other), 1, now, now, true));
        // Once nothing they hold could pass the age check, they go.
        let later = now + MAX_REQUEST_SKEW.as_secs() + 1;
        service
            .histories
            .lock()
            .forget_older_than(later - MAX_REQUEST_SKEW.as_secs());
        assert!(service.histories.lock().by_peer.is_empty());
        assert!(service.histories.lock().order.is_empty());
        assert!(service.first_sight(peer(100_000), Some(host), 1, later, later, true));
    }

    #[test]
    fn with_every_history_taken_the_oldest_goes() {
        let mut histories = Histories::default();
        let peer = |n: u32| {
            let mut peer = [0u8; 32];
            peer[..4].copy_from_slice(&n.to_be_bytes());
            peer
        };
        for n in 0..=u32::try_from(MAX_REQUEST_HISTORIES).unwrap_or(u32::MAX) {
            assert!(histories.start(peer(n), None));
        }
        assert_eq!(histories.by_peer.len(), MAX_REQUEST_HISTORIES);
        assert!(!histories.by_peer.contains_key(&peer(0)));
        assert!(histories.by_peer.contains_key(&peer(1)));
    }

    #[tokio::test]
    async fn a_member_can_hold_only_so_many_unanswered_offers() {
        let service = service();
        let _b = call(&service, B, announce(1, &[], 0)).await;
        let mut delivered = 0;
        for offer in 0..40u8 {
            delivered += call(&service, A, announce(1, &[offer], 0)).await.delivered;
        }
        // B's inbox holds 32, A may have 32 offers out: both caps meet at 32.
        assert_eq!(delivered, 32);
        assert_eq!(service.stats().pending_offers, 32);
    }

    #[tokio::test]
    async fn a_member_that_goes_takes_the_offers_made_to_it() {
        let service = service();
        let _b = call(&service, B, announce(1, &[], 0)).await;
        let a = call(&service, A, announce(1, &[80], 0)).await;
        assert_eq!(a.delivered, 1);
        assert_eq!(service.stats().pending_offers, 1);
        // B can no longer answer A's offer: A's place for it is free again.
        service.session_closed(B);
        assert_eq!(service.stats().pending_offers, 0);
        assert_eq!(service.stats().stored_sdp_bytes, 0);
    }

    #[tokio::test]
    async fn a_newer_membership_takes_the_place_and_an_old_leave_spares_it() {
        let service = service();
        let with = |membership: u64, body: ChunkMessageBody| match body {
            ChunkMessageBody::SwarmAnnounceRequest(mut request) => {
                request.membership = membership;
                ChunkMessageBody::SwarmAnnounceRequest(request)
            }
            other => other,
        };
        let leave = |membership: u64| {
            ChunkMessageBody::SwarmLeaveRequest(SwarmLeaveRequest {
                room: [1; 32],
                node: NODE,
                membership,
            })
        };
        let _b = call(&service, B, announce(1, &[], 0)).await;
        let old = call(&service, A, with(5, announce(1, &[90], 0))).await;
        assert_eq!(old.delivered, 1);
        // The client rejoins: a new member, and the old one's offer is gone.
        let new = call(&service, A, with(6, announce(1, &[], 0))).await;
        assert_ne!(new.member, old.member);
        assert_eq!(service.stats().members, 2);
        assert_eq!(service.stats().pending_offers, 0);
        // The old membership's announce is refused, and its leave ends nothing.
        let stale = service
            .handle(
                A,
                None,
                with(5, announce(1, &[], 0)),
                &CancellationToken::new(),
                Instant::now(),
            )
            .await;
        assert!(matches!(
            stale,
            Some(ChunkMessageBody::SwarmAnnounceResponse(
                SwarmAnnounceResponse::Refused(SwarmRefusal::Superseded)
            ))
        ));
        let _ = service
            .handle(A, None, leave(5), &CancellationToken::new(), Instant::now())
            .await;
        assert_eq!(service.stats().members, 2);
        // Its own leave ends it.
        let _ = service
            .handle(A, None, leave(6), &CancellationToken::new(), Instant::now())
            .await;
        assert_eq!(service.stats().members, 1);
    }

    #[tokio::test]
    async fn an_ended_membership_does_not_come_back() {
        let service = service();
        let token = CancellationToken::new();
        let membership = |membership: u64| {
            let ChunkMessageBody::SwarmAnnounceRequest(mut request) = announce(1, &[], 0) else {
                unreachable!("an announce");
            };
            request.membership = membership;
            ChunkMessageBody::SwarmAnnounceRequest(request)
        };
        let leave = |membership: u64| {
            ChunkMessageBody::SwarmLeaveRequest(SwarmLeaveRequest {
                room: [1; 32],
                node: NODE,
                membership,
            })
        };
        let superseded = |reply: &Option<ChunkMessageBody>| {
            matches!(
                reply,
                Some(ChunkMessageBody::SwarmAnnounceResponse(
                    SwarmAnnounceResponse::Refused(SwarmRefusal::Superseded)
                ))
            )
        };
        // A leave that overtook its own announce: the announce joins nothing.
        let _ = service
            .handle(A, None, leave(6), &token, Instant::now())
            .await;
        let late = service
            .handle(A, None, membership(6), &token, Instant::now())
            .await;
        assert!(superseded(&late));
        // Nor does an older membership's, after the newer one left.
        let late = service
            .handle(A, None, membership(5), &token, Instant::now())
            .await;
        assert!(superseded(&late));
        assert_eq!(service.stats().members, 0);
        // A newer membership joins.
        let _ = call(&service, A, membership(7)).await;
        assert_eq!(service.stats().members, 1);
        // A connection that closes ends no membership: the client carries on
        // in the same one over its next connection.
        service.session_closed(A);
        assert_eq!(service.stats().members, 0);
        let _ = call(&service, A, membership(7)).await;
        assert_eq!(service.stats().members, 1);
    }

    #[tokio::test]
    async fn an_older_membership_does_not_come_back_after_a_newer_one_goes_silent() {
        let service = service();
        let with = |membership: u64| {
            let ChunkMessageBody::SwarmAnnounceRequest(mut request) = announce(1, &[], 0) else {
                unreachable!("an announce");
            };
            request.membership = membership;
            ChunkMessageBody::SwarmAnnounceRequest(request)
        };
        // Membership 7 arrives first, then goes silent.
        let _ = call(&service, A, with(7)).await;
        service.sweep(Instant::now() + MEMBER_TTL + Duration::from_secs(1));
        assert_eq!(service.stats().members, 0);
        // The older 6, arriving late, does not come back; 7 itself may.
        let late = service
            .handle(A, None, with(6), &CancellationToken::new(), Instant::now())
            .await;
        assert!(matches!(
            late,
            Some(ChunkMessageBody::SwarmAnnounceResponse(
                SwarmAnnounceResponse::Refused(SwarmRefusal::Superseded)
            ))
        ));
        let _ = call(&service, A, with(7)).await;
        assert_eq!(service.stats().members, 1);
    }

    #[test]
    fn a_request_for_another_node_is_told_apart_before_its_history() {
        let service = service();
        assert!(service.names_this_node(&announce(1, &[], 0)));
        let ChunkMessageBody::SwarmAnnounceRequest(mut elsewhere) = announce(1, &[], 0) else {
            unreachable!("an announce");
        };
        elsewhere.node = [1; 32];
        assert!(!service.names_this_node(&ChunkMessageBody::SwarmAnnounceRequest(elsewhere)));
        assert!(service.names_this_node(&answer(1, [2; 16], 3)));
    }

    #[tokio::test]
    async fn one_host_holds_only_its_share_of_the_stored_sdp() {
        let service = service();
        let token = CancellationToken::new();
        let sdp = MAX_SWARM_SDP_BYTES;
        let offers = |room: u8| {
            ChunkMessageBody::SwarmAnnounceRequest(SwarmAnnounceRequest {
                room: [room; 32],
                node: NODE,
                membership: 1,
                offers: (0..8u8)
                    .map(|id| SwarmOffer {
                        offer_id: [id; 16],
                        sdp: "v".repeat(sdp),
                    })
                    .collect(),
                wait_ms: 0,
            })
        };
        // 24 rooms of 8 receivers each, from hosts of their own.
        for room in 0..24u8 {
            let receivers: IpAddr = format!("203.0.113.{room}").parse().expect("ip");
            for n in 0..8u64 {
                let session = SwarmSession::Browser(1000 + u64::from(room) * 8 + n);
                let _ = service
                    .handle(
                        session,
                        Some(receivers),
                        announce(room, &[], 0),
                        &token,
                        Instant::now(),
                    )
                    .await;
            }
        }
        // One host offers 8 into each room: more than its share.
        let host: IpAddr = "198.51.100.4".parse().expect("ip");
        let mut delivered = 0u32;
        for room in 0..24u8 {
            if let Some(ChunkMessageBody::SwarmAnnounceResponse(SwarmAnnounceResponse::Joined {
                offers_delivered,
                ..
            })) = service
                .handle(
                    SwarmSession::Browser(u64::from(room)),
                    Some(host),
                    offers(room),
                    &token,
                    Instant::now(),
                )
                .await
            {
                delivered += offers_delivered;
            }
        }
        assert_eq!(
            usize::try_from(delivered).unwrap_or(usize::MAX),
            MAX_STORED_SDP_BYTES_PER_HOST / sdp
        );
        // The rest of the budget is left for every other host.
        assert_eq!(
            service.stats().stored_sdp_bytes,
            MAX_STORED_SDP_BYTES_PER_HOST
        );
    }

    #[tokio::test]
    async fn the_stun_allowlist_counts_an_ipv6_network_once() {
        let service = service();
        let token = CancellationToken::new();
        for n in 0..32u16 {
            let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 9, 0, 0, 0, n));
            let _ = service
                .handle(
                    SwarmSession::Browser(u64::from(n)),
                    Some(ip),
                    announce(1, &[], 0),
                    &token,
                    Instant::now(),
                )
                .await;
        }
        assert_eq!(service.announcers.read().len(), 1);
        let neighbour = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 9, 0, 0, 1, 1));
        assert!(service.stun_allows(neighbour, Instant::now()));
    }

    #[test]
    fn ended_memberships_outlast_every_request_still_taken() {
        assert!(ENDED_MEMBERSHIP_TTL > 2 * MAX_REQUEST_SKEW);
    }

    #[test]
    fn one_connection_cannot_push_out_the_others_ended_memberships() {
        let mut state = State::default();
        let now = Instant::now();
        let host: IpAddr = "198.51.100.4".parse().expect("ip");
        let honest = SwarmSession::Browser(1);
        state.note_ended(honest, Some(host_of(host)), [1; 32], 5, now);
        // A connection ending ever newer memberships of one room holds one
        // place, and the queue does not grow past its bound.
        let flooder = SwarmSession::Browser(2);
        let other: IpAddr = "203.0.113.9".parse().expect("ip");
        for membership in 1..=(3 * MAX_ENDED_MEMBERSHIPS as u64) {
            state.note_ended(flooder, Some(host_of(other)), [2; 32], membership, now);
        }
        assert_eq!(state.ended.len(), 2);
        assert!(state.ended_order.len() <= 2 * state.ended.len() + 1024);
        // Nor many rooms past its own share.
        for room in 0..=u8::MAX {
            state.note_ended(flooder, Some(host_of(other)), [room; 32], 1, now);
        }
        assert!(
            state
                .ended_by_session
                .get(&flooder)
                .map_or(0, VecDeque::len)
                <= MAX_ENDED_PER_SESSION
        );
        // The newest of them are the ones kept.
        assert!(state.ended_covers(flooder, &[u8::MAX; 32], 1));
        assert!(state.ended_covers(honest, &[1; 32], 5));
        // A place ended again goes to the back: the oldest other goes first.
        let mut rotating = State::default();
        let session = SwarmSession::Browser(9);
        for room in 0..MAX_ENDED_PER_SESSION {
            let room = u8::try_from(room).unwrap_or(u8::MAX);
            rotating.note_ended(session, None, [room; 32], 1, now);
        }
        rotating.note_ended(session, None, [0; 32], 2, now);
        rotating.note_ended(session, None, [200; 32], 1, now);
        assert!(rotating.ended_covers(session, &[0; 32], 2));
        assert!(!rotating.ended_covers(session, &[1; 32], 1));
        assert!(rotating.ended_covers(session, &[200; 32], 1));
        // All go once nothing they cover could be taken.
        state.forget_ended(now + ENDED_MEMBERSHIP_TTL);
        assert!(state.ended.is_empty() && state.ended_order.is_empty());
        assert!(state.ended_by_session.is_empty() && state.ended_by_host.is_empty());
    }

    #[tokio::test]
    async fn a_waiting_announce_of_a_replaced_membership_is_not_told_it_joined() {
        let service = service();
        let with = |membership: u64, wait_ms: u32| {
            let ChunkMessageBody::SwarmAnnounceRequest(mut request) = announce(1, &[], wait_ms)
            else {
                unreachable!("an announce");
            };
            request.membership = membership;
            ChunkMessageBody::SwarmAnnounceRequest(request)
        };
        let waiting = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .handle(
                        B,
                        None,
                        with(5, 10_000),
                        &CancellationToken::new(),
                        Instant::now(),
                    )
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(service.stats().waiting, 1);
        let _ = call(&service, B, with(6, 0)).await;
        let reply = tokio::time::timeout(Duration::from_secs(2), waiting).await;
        assert!(matches!(
            reply,
            Ok(Ok(Some(ChunkMessageBody::SwarmAnnounceResponse(
                SwarmAnnounceResponse::Refused(SwarmRefusal::Superseded)
            ))))
        ));
    }

    #[tokio::test]
    async fn one_host_holds_only_so_many_places() {
        let service = service();
        let join = |n: u16, ip: IpAddr| {
            let service = Arc::clone(&service);
            async move {
                let mut peer = [0u8; 32];
                peer[..2].copy_from_slice(&n.to_be_bytes());
                service
                    .handle(
                        SwarmSession::Native(peer),
                        Some(ip),
                        announce(1, &[], 0),
                        &CancellationToken::new(),
                        Instant::now(),
                    )
                    .await
            }
        };
        let joined = |reply: &Option<ChunkMessageBody>| {
            matches!(
                reply,
                Some(ChunkMessageBody::SwarmAnnounceResponse(
                    SwarmAnnounceResponse::Joined { .. }
                ))
            )
        };
        // Identities of one IPv6 /64, each on its own address in it.
        let host = |n: u16| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 7, 0, 0, 0, n));
        for n in 0..u16::try_from(MAX_MEMBERS_PER_HOST).unwrap_or(u16::MAX) {
            assert!(joined(&join(n, host(n)).await));
        }
        let refused = join(1000, host(1000)).await;
        assert!(matches!(
            refused,
            Some(ChunkMessageBody::SwarmAnnounceResponse(
                SwarmAnnounceResponse::Refused(SwarmRefusal::TooManyRoomsForPeer)
            ))
        ));
        // Another host is not held back; one that goes frees its place.
        assert!(joined(
            &join(2000, "198.51.100.4".parse().expect("ip")).await
        ));
        let mut first = [0u8; 32];
        first[..2].copy_from_slice(&0u16.to_be_bytes());
        service.session_closed(SwarmSession::Native(first));
        assert!(joined(&join(1000, host(1000)).await));
    }

    #[tokio::test]
    async fn a_member_that_goes_leaves_no_offer_in_another_inbox() {
        let service = service();
        let _b = call(&service, B, announce(1, &[], 0)).await;
        for offer in 0..4u8 {
            let _ = call(&service, A, announce(1, &[offer], 0)).await;
            service.session_closed(A);
        }
        assert_eq!(service.stats().pending_offers, 0);
        assert_eq!(service.stats().stored_sdp_bytes, 0);
        assert_eq!(call(&service, B, announce(1, &[], 0)).await.inbox, []);
    }
}
