# ADR-0026: Clients reading the same file share its records; nodes introduce them and stay the last seed

- **Status:** Proposed
- **Date:** 2026-10-27
- **Decision owners:** <pending>
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** [ADR-0015](./ADR-0015-direct-browser-clients-over-webrtc-direct.md)
  (browser sessions over WebRTC Direct, whose UDP socket also answers STUN
  here), [ADR-0023](./ADR-0023-spread-hot-reads-and-refuse-full-browser-sessions.md)
  (option 4, "browser peer-to-peer sharing", deferred to its own ADR: this
  one), [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489) (STUN),
  [RFC 8445](https://www.rfc-editor.org/rfc/rfc8445) (ICE),
  [RFC 8831](https://www.rfc-editor.org/rfc/rfc8831) (WebRTC data channels)
- **Implementation:** ant-protocol (swarm messages), saorsa-transport (plain
  STUN Binding answers on the WebRTC Direct socket), saorsa-core (a send on
  one named connection only), ant-node (the swarm rendezvous), ant-client
  (the swarm in every client, native and browser)

## Context

Every reader of a file asks the same close group for the same records. ADR-0023
spread hot reads across the group and made full browser sessions refuse
cleanly, but the group's capacity is still the ceiling: a node admits a bounded
number of browser sessions and bulk replies, so a popular file (a film many
people watch at once, a release everyone fetches) is served at the rate seven
nodes can serve it, however many readers there are.

Readers of one file hold exactly the records the next reader needs. Records are
content addressed, every client checks each record against its address
(`ant-core/src/record.rs`), and public records are byte-identical for every
reader. So a record from another reader is as good as one from a node, once it
passes the check. BitTorrent peers share pieces the same way. What clients lack
is a way to find each other and connect:

- Browsers cannot accept connections; two browsers connect only through WebRTC,
  which needs a signalling channel to swap an offer and an answer, and a STUN
  server to learn the public address the other side can reach.
- Native clients run in `NodeMode::Client`, are not DHT members, and are
  usually behind NAT too.
- The network has no third-party service to lean on. A WebTorrent tracker or a
  public STUN server would learn which addresses read which file, and would be
  a single point of failure the network does not otherwise have.

The nodes closest to a file are already the parties every reader talks to. They
can introduce readers to each other on the connections those readers already
have, and answer their STUN requests on the WebRTC Direct UDP socket they
already run.

## Decision Drivers

- Load on the close group should grow with the data, not with the number of
  readers.
- No new binary and no third-party service: nodes and clients only.
- Every client takes part, browser and native alike, always: a swarm nobody
  joins serves nobody.
- A peer can never make a client accept wrong bytes, and a slow or hostile
  peer can only cost a short wait before the nodes are asked.
- A node's cost is small and bounded by hard limits, with no switch to turn it
  off or tune it.
- A release that adds this must not break older clients or older nodes, in
  either order of rollout.

## Considered Options

1. **A separate signalling service** next to the nodes (built as `ant-signal`
   and reviewed, then dropped). It works, but it is one more binary to run and
   secure, someone has to run it, and readers would depend on it.
2. **Third-party WebTorrent trackers and public STUN servers.** Free to use,
   but they see who reads what, and the network would stop working the way it
   should whenever they do.
3. **Peer records in the DHT** ("I hold file X, reach me at Y"). Clients are not
   DHT members, browsers cannot be reached at an address, and two clients would
   still need someone to carry their offer and answer.
4. **Nodes relay the data** (a TURN-like role). Every byte would still cross a
   node, so nothing is offloaded.
5. **Nodes introduce readers and answer their STUN; readers share records over
   WebRTC data channels; nodes stay the last seed** (chosen).

## Decision

We adopt option 5.

### Rooms

The readers of one file form a *room*. Its key is the address the file's
root DataMap would have as a public record: `compute_address(rmp_serde(root))`.
Every reader derives the same key whichever way it reached the file (by public
address, through a manifest, which may hold a shrunk or a root map, or from a
private map), once it has resolved a shrunk map to its root. For a file whose
public map is its root, the key is the file's public address. A reader
announces itself at the `SWARM_RENDEZVOUS_NODES` (2) nodes closest to the key
that host rooms, so two readers whose views of the close group differ
slightly still share one, and readers still meet while some of the closest
nodes predate rooms: it looks up the 8 nodes closest to the key and passes
over those that host none (see Older nodes). A node hosts rooms only once
browsers can reach it: until its browser listener has an endpoint, and so a
STUN server to name, it refuses every announce as `NotHosting`, and a client
passes it over at once, with no pause. Native readers so pass over the same
nodes browsers never see (a relay-only node, or one
built without the listener), and meet the browsers at the closest nodes
both can reach, rather than at nodes no browser comes to and that give them
no STUN.

### Wire (ant-protocol, `src/swarm.rs`)

Six `ChunkMessageBody` variants are appended after the pointer messages, at
discriminants 14 to 19; existing variants keep their discriminants.

| Request | Reply | Purpose |
|---|---|---|
| `SwarmAnnounceRequest { room, node, membership, offers, wait_ms }` | `SwarmAnnounceResponse::{Joined, Refused, Error}` | Join or stay in a room, hand over WebRTC offers, collect signals |
| `SwarmAnswerRequest { room, node, to, offer_id, sdp }` | `SwarmAnswerResponse::{Delivered, Unmatched, Error}` | Answer an offer the node delivered |
| `SwarmLeaveRequest { room, node, membership }` | `SwarmLeaveResponse::{Left, Error}` | Leave |

`node` is the peer id of the rendezvous node the request is for.
`membership` names one of the client's memberships of the room: a number that
grows each time the client joins the room anew. A node compares only the
numbers of one connection identity (a native client's peer id, made afresh
each run, or one browser connection). It keeps each connection's newest
membership of a room: an announce naming a newer one starts a member in place
of the old (whose signals and offers go with it), and a leave ends the
membership it names, or an older one in its place. Admitting a membership
marks every older one of that connection in that room as replaced. A
membership the client ended (left, or replaced by a newer one) is remembered for twice the
10-minute signed-time window and 2 s more, as long as a request sent before
it ended can still be taken (one per connection and room however often it
ends a newer one; at most 64 per connection, 256 per host and 16384 in all,
past which the connection's, host's or node's oldest goes, so the newest
ends are the ones kept; a forgotten one can come back only as a member that
is dropped once silent): an announce naming it, or an older one, is
refused
(`SwarmRefusal::Superseded`), even one that arrives after its own leave. So a
request of a membership the client left, however late it arrives, cannot end
or take over a newer one, nor bring the old one back. A membership dropped
because its connection closed or it went silent is not ended: the client
carries on in it over a new connection. A waiting announce whose member was
replaced or dropped meanwhile is answered `Superseded`, not `Joined`.

`Joined` carries the member's id, the room's size, how many offers went out,
the signals waiting for the member (offers from others, answers to its own),
and the node's STUN URL (`stun:<its WebRTC Direct address>`).

Limits both sides check: at most 8 offers per announce, 16 KiB per SDP, 32
signals and 48 KiB of SDP per reply (inside the browser transport's 64 KiB
small-response bound, asserted at compile time), at most 4 STUN URLs of at
most 256 bytes, and a wait of at most 20 s. `MAX_SWARM_REQUEST_BYTES` bounds
an encoded request, so a node refuses a longer one from its length before
decoding it, and a client validates every reply before acting on it,
announce, answer and leave alike, an error's text included (at most 512
bytes).

**Candidates.** An offer or answer is another client's, and its receiver
sends ICE connectivity checks to every candidate in it before anything proves
who made it. Both sides therefore pass each SDP through the protocol's
`constrain_swarm_sdp`: UDP candidates only, naming an IP address that is not
unspecified, multicast or broadcast, or an mDNS `.local` name, at most 16. A
node relaying an SDP also drops every candidate whose address is public and
not the sender's own host, as the node reaches it on that request (an IPv4
address, or an IPv6 /64). Local addresses and mDNS names stay only where the
node and the client reach each other at local addresses (a network of their
own, such as a test network or a LAN deployment): the node keeps them only
for a sender it reaches at a local address, and a client applies them only
from a node it reached at one, loopback ones only over loopback. On a network
reached at public addresses, readers meet by their public (server-reflexive)
addresses alone, so two readers behind one NAT need it to hairpin. A stranger
in a room therefore cannot point other readers' checks at a third party, nor
at the readers' own home networks, and a hostile node can point them at 16
addresses at most per SDP. Receivers read SDP leniently (webrtc-rs trims an
attribute's value and skips a carriage return before a line, Chrome takes an
attribute name followed by a space, Firefox names attributes in any case), so
a line any of them may read as a candidate or a DTLS fingerprint stays only
in its one standard form (`a=candidate:` or `a=fingerprint:`, then a value
with no whitespace around it), and a line with a carriage return anywhere but
before its line feed is dropped: what a receiver reads is exactly what was
checked. The filtered SDP holds no more memory than its length, and the node
charges a stored SDP the memory it holds. Honest SDPs only lose candidates,
so a link's binding to both ends' fingerprints does not change.

**Decoding.** The offers, inbox and STUN server lists are refused while
decoding once past their limits, so a request or reply of a legal length
cannot make its receiver build thousands of entries before `validate` runs;
and a message with bytes after its end is refused, so a small reply cannot be
padded out to the wire limit. Every enum in
the module is encoded by variant position; a test pins each tag, and variants
may only be appended.

### The node's part (ant-node, `src/swarm.rs`)

- **Identity.** The node names each member itself, from the authenticated
  connection (a native peer id, or the number of a browser connection on this
  node). A browser's session is its connection. A native client's request is
  signed by its key but not bound to the connection it came on. So every
  request names its rendezvous node, and a node refuses one naming another:
  a request one node saw cannot be replayed at the room's other node. A node
  also drops a native request whose signed time is more than 10 minutes from
  its own clock, more than 5 s older than that client's newest, or whose id
  it has seen, so one cannot be replayed at the same node either. A request
  naming another node is answered with an error before it touches that
  history, so a node that saw a client's request cannot send it on to make
  the client's later requests elsewhere look stale. Only an
  announce or a leave starts a client's history (an answer comes from a
  member, which announced first; a leave may overtake the announce it ends);
  a host keeps at most 256 histories, 16384 in all,
  the oldest made forgotten first, and a history goes once nothing it holds
  could pass the 10-minute check.
- **Introductions.** Each offer goes to a different other member, picked at
  random. An answer is passed on only to the member whose offer the node
  delivered to the answerer, once, before it expires. Unanswered offers, and
  signals waiting for their member, expire after the protocol's
  `SWARM_SIGNAL_TTL_MS` (70 s), which a client checks at compile time against
  the slowest answer any client gives: 11 s to its next announce (a
  browser's 3 s pause and one 8 s step to make that round's offers), 30 s
  for an announce that may already be on its way (a native one may wait
  20 s, with 10 s for the request and reply), 8 s to make the answer and
  10 s for the answer's request. An offering client keeps its offer for its
  own announce's time on each way, the poll gap and the node's 70 s: 141 s
  natively, 101 s in a browser, whose announces do not wait. It drops
  expired offers before and after every announce, and all of them before a
  pause after a failure, so an unanswered offer holds its place in the
  room's connection limits at most that long and one announce more. A link
  a client answered has 79 s to open and be proven, since its answer still
  has to reach the offerer; one it offered has 20 s once it has the answer. A member that stops
  announcing is dropped after 60 s; a connection that closes leaves all its
  rooms at once.
- **Long poll, native only.** A native client's announce with nothing waiting
  may be held until a signal arrives, the wait ends, the member is dropped, or
  the node stops; one announce per member waits, and no lock is held
  meanwhile. Native swarm requests are routed apart from chunk requests, with
  their own task budget, so a waiting announce never delays a GET. A browser's
  announce is never held: it would keep one of the browser session's few
  request slots, and its byte reservation, from the browser's reads. Browsers
  ask again after 1 s while a signal is likely on its way (they just acted on
  one, or made an offer within the last 10 s) and after 3 s otherwise: in a
  room larger than its members' links can hold, most offers go unanswered,
  and their makers wait at the slower pace. At a node's browser listener,
  swarm requests run on a budget of their own (64 a second in all, 8 from one
  source): every request takes a token from the budget the reads share as
  it arrives, and a swarm request the swarm's budget has room for gives it
  back, so announces never spend what reads need; one past the swarm's
  budget keeps that token and is refused, without closing the channel the
  reads use, and its maker backs off as from any refusal. A request that
  arrives once the reads' budget is spent is taken on the swarm's instead,
  since only the opened frame says whether it is a swarm request: one that
  is goes on, and anything else gives the swarm its token back and is
  refused as over the request rate, as before.
- **Closing.** A connection that closes leaves all its rooms at once. No
  request of it still being handled can act after the close (announce, answer
  or leave), nor any request older than a minute. A member that goes takes
  with it its signals still queued for others and the offers others made to
  it, since none can be answered now.
- **Hard limits**, no configuration: 4096 rooms, 256 members per room, 16384
  members in all, 4 rooms per connection, 64 members per host (an IPv4
  address or an IPv6 /64, since a native client's identities cost nothing to
  make), 32 unanswered offers per member,
  16 MiB of stored SDP (2 MiB for the offers and answers of one host's
  members), 1024 waiting announces (more are answered at once), and
  a fixed number of swarm tasks (more requests are dropped).
- **Every node.** A node hosts the rendezvous whether it stores chunks or
  not, and devnets route native swarm requests the way nodes do.
- **Replies.** A reply to a native client whose connection closed meanwhile,
  or from a node stopping, is dropped rather than sent, and a reply goes
  only on a connection the client still has, so the node never dials a
  client that left. A signed message is not bound to the connection it came
  on, and saorsa-core maps a client's identity to every connection a message
  signed by it arrived on: a node that saw a client's message could send it
  on to another node, which would then take the sender's connection for the
  client's too. So a native reply goes on the connection the request came
  on and no other, through saorsa-core's new `send_message_on_channel`
  (never another of the peer's connections, never a dial). Other protocols'
  replies still go by peer id; moving them to the same call is a separate
  change. Offers are handed on in order, so `offers_delivered` names exactly
  the first ones, and the client drops the rest at once.
- **STUN.** The WebRTC Direct UDP socket also answers a plain STUN Binding
  request (no USERNAME, no comprehension-required attribute, a valid
  FINGERPRINT if present) with XOR-MAPPED-ADDRESS. The answer (32 bytes for a
  20-byte IPv4 request, 44 for IPv6) is larger than the request, and a UDP
  source can be forged, so it is bounded three ways: only hosts (an IPv4
  address or an IPv6 /64, as the responder's own limits count them) that
  announced in a room within the last 60 s are answered, so a victim's
  address is answered only by the few nodes of its own rooms; each source (an
  IPv4 address or an IPv6 /64) gets at most 10 answers a second (burst 20,
  4096 sources tracked); and the socket sends at most 2000 answers a second
  in all, after a burst of at most 4000. A request counts against both
  limits or neither: only requests that would be answered count, so one
  source over its rate, or sending malformed requests, costs the others
  nothing, and a request the socket's limit refuses costs its source
  nothing. Every check runs on the raw bytes without allocating, the answer
  is built only once both limits grant it, and a refused plain request is
  dropped rather than passed to the connection handling that shares the
  socket. A request with a comprehension-required
  attribute is left alone rather than answered with `420 Unknown Attribute`:
  no ICE agent sends one, and an error answer is one more reply a forged
  source could draw. Policy lookups take a read lock, so the packet path
  rarely waits on announces.
- **Capability.** A node advertises `swarm_rendezvous` in its browser HELLO.

### The client's part (ant-client, `ant-core/src/swarm/`)

Every client takes part, always, on both builds: a browser through its own
`RTCPeerConnection`, a native client through webrtc-rs (the stack
saorsa-transport's WebRTC Direct already uses).

- **Joining.** Only a valid root map has a room (not a child map, one whose
  records index, with at least the 3 records a file has), checked before
  joining, so a bad map never takes a valid room's place; and only one with
  at most 262,144 records (about 1 TiB of 4 MiB records), all of which a
  room holds, so a room always shares its whole file. A larger file is read
  from the nodes alone. Every read of a file joins its file's room as soon
  as it has the root map (native `file_download*` and `data_download*`;
  in a browser, opening a reader, a public or private download, and a
  stream), and a browser reader joins again on a read if reading other
  files has left the room since. Joining starts the room's own task and
  returns at once: the other readers are found beside the reads from the
  nodes, which never wait for that (see Reading), so a slow or failing
  discovery leaves the reads from the nodes as they were. The small DataMap
  records come from the nodes. A room joined by a read asks the nodes for
  nothing (no lookup, no announce) until that read's first record of the file
  is in, or for 30 s if none comes: its discovery so never competes with a
  download's first record for the nodes, the client's connections or its
  CPU. (With discovery started at the open, the first chunk came 0.3 to
  6.5 s later in 6 of 7 lab pairs whose nodes were the bottleneck.) A room
  joined on request (`join_swarm`) starts at once. A client's read of a
  file's record keeps the file's room in use for as long as it runs, however
  long the nodes take. Joining past 4 rooms leaves the room unread longest, once no
  read has used it for 30 s; with every room still read, the join waits (at
  most 2 do) and is made at a later read of one of the file's records once a
  room has gone unread, the file meanwhile read from the nodes. A client
  reading more files than that at once so cannot make every read a new
  membership (a key, a lookup, links that never open), and a long download's
  room is never left for a file opened beside it; at most 8 rooms left at a time tell their nodes so (each
  leave bounded to 10 s in all), and one left past that leaves quietly, its
  places there expiring after 60 s. A room left tells its nodes even if it
  never saw its join confirmed (a reply can be lost). Two places are not
  told: a room left quietly, and a node a rendezvous place stops using after
  3 failures or 10 minutes (the place may come back to it in the same
  membership). Those memberships are not ended at the node; they go after
  60 s of silence, and a late announce of one can bring it back only until
  it is silent that long again. A room joined again is a new membership:
  its number is newer, so nothing the old one still sends can end it, and
  links made for the old one are not kept by the new one. A room left or shut
  down drops its record list at once. `Client::join_swarm` and the browser's
  `joinSwarm` let an application join before reading, so the client meets
  the others first. A page tells which file each link and count belongs to
  from the channel's label, from the `Swarm room <tag>` a browser read
  reports when it resolves its file, and from per-room counts
  (`swarm_room_stats`, `swarmRoomStats`).
- **One swarm per identity.** Rendezvous nodes know a native client's
  memberships by its node identity, so clients built on one native node
  share one swarm. A membership continued over a connection from another
  address counts against that address from then on, if it has room. Each
  browser client has its own sessions, and its own swarm.
- **Room-scoped records.** A room knows its file's records: those its root
  map lists. A record is asked of peers, kept, announced and served only
  within a room whose file holds it, so a peer never learns what else a
  client read. Reads of any other record (existence checks, a `chunk get` by
  address, DataMap records, a shrunk map's wrappers included) neither ask
  peers nor keep the record.
- **Proven links.** The room's key is the root map's address; next to it a
  client derives the room's *secret* from the root map's bytes, which a node
  that knows only the key of a private file's room does not have. Each end
  of a new link sends `Proof`: a keyed BLAKE3 MAC, under the secret, of its
  role (offerer or answerer), the offer's id, and the DTLS fingerprints of
  the offer and the answer as both ends saw them. Each WebRTC stack checks
  the peer's DTLS certificate against those fingerprints, so a node that put
  itself in the middle, with an offer and an answer of its own, cannot pass
  one client's proof on to the other. The secret proves nothing about which
  member a link reaches, since every member knows it, so each membership of
  a room also has an ML-DSA-65 key of its own: `Hello` carries the public key
  (1952 bytes), the member's name in the room is a hash of it, and `Proof`
  also carries the member's signature (3309 bytes) over its role, the offer's
  id and the same fingerprints. A member that names itself by another's key
  cannot sign for it, and a signature made for one link proves nothing on
  another, so no member can pose as another to settle away its links or take
  its names. A link opens only after the peer's
  `Hello` and then its `Proof`, which must check out within 20 s of the
  answer on a link this client offered, or 79 s on one it answered (which
  starts before the offerer has had the answer): until then
  no `Have` is sent, nothing is served, no duplicate is settled, and any
  other message ends the link. A public file's secret is open to anyone with
  its address, as its records are. A client keeps one link per member, as
  the node that introduced it names it, so a member cannot fill the room's
  links by connecting again and again under new names: one answer at a time
  per member and 8 in all, each held until the node has taken the answer,
  taken before any negotiation; until its proof, one link each
  way per member (two clients offering to each other at once make
  one each way, and settle on one once open); once open, a member linked
  again under another name keeps its first link.
- **STUN.** A client uses only the STUN URLs a rendezvous node names at an
  IP address the client reached that node on, two per node: natively the
  remote address of an authenticated connection to it, in a browser the
  host of a WebRTC Direct session with it. The addresses a node advertises
  are its own claim, so it cannot send a client's STUN requests, and with
  them its address, to another host. With no such connection, none of that
  node's STUN URLs are used. A native connection through a relay is named
  by the relay's address, a host the client already sends to.
- **Meeting.** The two rendezvous places never use the same node: a place
  whose lookup puts the other place's node at its own position takes the
  first node of the lookup the other does not use. Offers go through every
  rendezvous node, as many as that node
  has members the client has no link or connection being made to there,
  each node counted alone (so two readers whose views of the close group
  share only one node still meet there); offers from others are answered
  while the client wants links (8 per room, 16 in all, counting the
  connections being made). A link made through one node to a peer that is
  also a member of the other settles with its duplicate, and the link kept
  then counts at both nodes, so the nodes do not keep doubling each other's
  offers. A room looks its nodes up once for both places, and one lookup,
  found or failed, serves them for 30 s; a place takes a node again when its membership ends
  (after 3 failures in a row, or 10 minutes), so a node that goes is
  replaced while the other carries on; its STUN URLs are dropped as the
  membership ends. Two links between the same pair (met
  through both nodes, or crossing offers) settle on the one both ends pick,
  told apart by the name the client has in that room alone (from its key for
  that membership), so peers meeting it in two rooms cannot tell it is the
  same client by its name or key. Its addresses may still let them link
  the two: each connection's WebRTC candidates carry whatever host and
  public addresses it gathers (see below for native offers), which are often
  the same across rooms, though not reliably so (shared NATs, changed
  interfaces, browsers' mDNS names). The swarm gives no unlinkability at the
  network level. The end that
  closes a duplicate stops using it at once but keeps its connection 2 s
  more, still counted against the link limits: the other end may not have this end's proof on that link yet, and
  without it would see a link that failed rather than a duplicate, never
  learn that both reach the same peer, and offer that member again every
  few seconds (seen between a native and a browser client). Signalling is
  non-trickle, with up to 3 s of ICE gathering, and a browser takes the page's
  ICE gathering turn after any connection to a node waiting for it (see
  Discovery is bounded). Every negotiation step (making an offer, answering
  one, applying an answer) ends after 8 s, or as soon
  as the room is left or the client shuts down, and a step that ends closes
  the connection it was making; the swarm is never held across one, so a
  native client dropped meanwhile still shuts its swarm down. A connection
  being made through either node counts at both until it is a link, so a
  reader starting out does not offer through both at once to a peer of
  both. An announce is bounded as a whole, waiting for the transport
  included, so a busy browser session cannot hold a round's offers past
  their time. A native
  announce that comes back empty well before the wait it asked for (the node
  had no place for it to wait) is followed by a 2 s pause, not another at
  once, and a native client starts announces at one node at least 1 s apart
  whatever the replies hold. A room starts at most 8 answers to other
  members' offers in 20 s, so a node that hands out offers of members it
  makes up, well formed or not, costs a bounded number of negotiations
  however fast it replies. A link has exactly one data
  channel, labelled `ant-swarm-<room tag>`: the tag is 16 hex digits derived
  from the room's secret, so it names the room and says nothing else, and an
  answerer refuses a channel labelled for another room. Another channel
  opened by the peer, a text message, or a message longer than the wire
  allows ends the link before anything is copied.
- **Sharing.** Over the data channel, peers say which records they hold
  (`Have`), ask (`Get`), and answer with 16 KiB `Piece`s, `Missing` or `Busy`.
  Every message is bounded before anything is allocated for it; every piece
  but a record's last is a full frame; a channel holds at most 257 messages
  unread (a bound of 256 plus the one sender's place) and, unsent, 256 KiB
  plus the message that crossed it, about 272 KiB.
- **Reading.** A record the client's swarm holds already (checked when it
  came) is used first. Otherwise (and except for two native downloads whose
  data chunks come from nodes only: one with download diagnostics, whose
  figures count the nodes' answers, and the peer-report download, which
  still shares what it reads and may resolve a large file's map as any
  other read does) a read asks peers only for a record a linked
  peer in the record's room said it holds. Peers complement the nodes and
  never hold a read up: a read that asks a peer gives it the read's hedge
  delay (3 s in a browser, 1 s natively: the time a node gets before a
  second is asked). Past that, the peer keeps the read while, at its average
  rate so far, the whole record arrives within the read's patience, and for
  the patience at most (measured on the clock from when the peer was asked,
  so timers that fire late on a busy page do not stretch it): as long as reads that went to the nodes have lately
  taken to have their records (a running average), at least twice the hedge
  delay, and never past the 12 s a peer has to send a record. Then, or as
  soon as the peer falls off that pace or fails, the read asks the nodes
  beside it, and the first checked record wins: a node read that ends
  without one (the nodes refuse, are busy or have none) leaves a peer still
  sending to finish within its own deadline, and only then is the read
  answered as the nodes answered; the node limiter still learns of the
  nodes' miss. A slow or failing peer so
  delays a read by the patience at most, which is about what a node read
  started then would take, and by the hedge delay unless it was on pace to
  beat one. (A node read started while the peer is still sending costs the
  node's bytes even when the peer wins; with a fixed 3 s window, six
  staggered readers in the lab used 1 % more node bytes than nodes alone.) A browser read still waiting
  for its turn at the nodes, with no GET sent, takes its record from a
  linked peer that offers it meanwhile (it looks every 250 ms) while it
  keeps its place in that queue: if the peer fails or is slower, the node
  read goes on as if no peer had been asked. A read asks up to 2 peers in
  all, however often it asks (a
  peer whose record fails its check counts as one; a link closed meanwhile as the
  duplicate of one kept does not, and the read goes on to its twin, waiting
  up to 2 s for the twin to say what it holds), with 2 s to send each next
  piece, a deadline of 2 s plus the record's size at 512 KiB/s, and 12 s for
  the read in all, from its first ask; a peer that stalls or runs past its record's time is
  passed over for 30 s (the read's own time running out does not count
  against it). A
  browser download asks for its records in an order of its own, picked at
  random, as BitTorrent picks pieces: a download keeps up to 8 records in
  flight (4 at first outside Chromium), and readers of one file who start together and ask in the same
  order would hold the same records at every moment, and want the same next
  ones, so none would have a record another is still waiting for. A
  download delivers its chunks in any order, so its order costs it nothing;
  a stream or a range read asks in the order its reader reads. A client asks one link for one record at a time: in
  Chromium, two records sent at once on one data channel, a few pieces of
  each in turn, stalled it for seconds (a 2 MiB record took 3.6 to 5.3 s
  that way, 66 to 656 ms alone). One more read may wait its turn at the
  client, where the wait is seen, keeping the link busy back to back; reads
  past that go to the nodes rather than queue behind a peer that may be
  slower than they are (on a local network, queueing made the last of four
  readers starting 1.5 s apart 11.5 s slower than with no peers at all); at most 8 records come from peers at once, and reads past that go
  to the nodes, as do the reads of a hidden browser page (a tab in the
  background), whose timers the browser slows to a second or more; a page
  hidden mid-read leaves the peers for the nodes at once, on its
  `visibilitychange` event. A record being received holds only the pieces that came
  (grown as they arrive, doubling from 64 KiB and never past the record's
  size), so a peer that names a large record and stops costs at most about
  twice what it sent, and never less than 64 KiB, and records being
  received hold at most 8 records' bytes. A record that fails its check ends
  that link; pieces out of order end it too.
- **Existence checks never ask peers.** `chunk_exists` (used before uploads to
  skip stored records) asks only nodes, and records from peers stay out of the
  chunk cache that answers it: another client holding a record says nothing
  about whether the network stores it.
- **The node limiter sees only nodes.** A record from a peer does not feed the
  adaptive fetch limiter, which measures how the nodes are coping, including
  the reads browser read-ahead holds for; after a fallback, only the time the
  nodes took counts.
- **Serving.** Records fetched from nodes, or from peers and checked, go into a
  store of 256 MiB (native) or 64 MiB (browser), oldest dropped first, and so
  do records a read finds in the chunk cache, so records read before the
  room was joined are offered too. Records a client already holds when it
  joins a room are told to the room's links as the room learns its file's
  records, so a link that opened first still hears of them. A client sends at
  most 4 records at once, and starts no send past 1 while reads of its own
  are running (sends already running when a read starts finish; the count
  is taken in one step, so two links never both take the last place): a
  record sent costs the sender's CPU and line, which its own download needs
  first
  (in the lab, readers each held to one CPU core and sending 4 at once while
  downloading took up to 40 % longer than nodes alone; sending 1 at a time,
  they were no slower); a client done reading sends 4,
  2 per link, one more than a peer asks for at once (a record the peer gave
  up on counts until its next piece sees that, and the peer's next ask may
  come first), and answers `Busy` past that; an ask cancelled and made again under the same id is a new transfer,
  and the old one stops. A record, or any other message,
  that takes more than 20 s to send (a peer that stopped reading) ends the
  link. Messages take turns on a link in order, and a record lets the
  others, and newly arrived asks, have the channel every 64 KiB, so records
  sent at once interleave rather than one taking every turn (a browser send
  that need not wait never yields by itself; the browser yields through a
  posted message, not a timer, which background tabs slow). A browser waits on a full
  channel for
  its `bufferedamountlow` event rather than a timer: browsers slow timers in
  tabs that are not in front to one a second, which would cap a tab left
  seeding at a quarter of a megabyte a second.
- **Older nodes.** A browser sends swarm messages only to nodes that advertise
  `swarm_rendezvous`: an older node closes the channel on a message it cannot
  decode, which would fail the reads in flight on it. The browser client's
  network adapter must say which nodes do (the client's own does); a client
  on an adapter that cannot joins no room and reads from the nodes alone. Older nodes drop the
  messages of a native client silently, which costs that client a timeout.
  A rendezvous place passes over, for 10 minutes, a node a session says
  hosts no rooms (at once, from its capabilities, and still once that
  session has closed) and one that never let the client join in a
  membership (after its 3 failures), and takes the next closest of the
  nodes the room looked up (a room remembers as many such nodes as its
  lookups can name in 10 minutes, 160); readers that see the same
  nodes pass over the same ones, so they still meet. With none left, a place
  tries again less and less often, doubling up to 5 minutes. Reads go to the
  nodes as before throughout. (Without this, a room whose closest node
  predated rooms never formed: in a lab network with 10 of 56 nodes on the
  previous release, six readers starting together met no one.)
- **Discovery is bounded.** Per room: one lookup of its nodes at a time and
  at most one per 30 s for both places, two places, each with one announce in
  flight (a browser asks again after 1 s while a signal is likely on its way
  and after 3 s otherwise, within the node's swarm budget; a native announce
  is held at the node for up to its wait, and announces at a node start at
  least 1 s apart),
  at most 2 offers per announce, each a WebRTC connection with up to 3 s of
  ICE gathering and every negotiation step bounded, and at most 8 links;
  per room, at most 8 answers started in 20 s; per client: 4 rooms, 16
  links, 8 answers being made, 4 records sent (1 while any of its own reads
  runs) and 8
  received at once. In a browser that makes connections take turns to
  gather ICE (every engine but Chromium), the swarm's own connections take
  the page's turn only while it is free and no connection to a node waits
  for it, and a room's lookup asks one node at a time, dials each only then,
  and warms no connections to the nodes it learns of; in any browser a room's
  lookup never starts the seeds' bootstrap (which opens several connections
  at once): it starts from the routes the reads' own lookups found, waiting
  up to 10 s for one, and with none (a tab left seeding whose routes went
  with its network) from one seed, the seeds tried one at a time in the
  discovery turn; discovery so holds at
  most one turn at a time, and a read whose connection starts while it does
  waits for that one turn, at most 1 s (the longest a connection holds the
  turn). `swarm_stats().discovery` (`swarmStats` in a browser)
  counts lookups, announces and their failures by cause, the signalling
  bytes, offers made, delivered and received, answers sent and received,
  channels opened, and links proven or failed. In lab runs of six browser
  readers of a 128 MiB file, each staying about 3 minutes after its
  download, each reader sent 28-47 KB of swarm requests (one lookup, about
  one announce a second) and received 14-22 KB of offers, answers and STUN
  names over its whole stay.
  A browser's pool keeps 64 node sessions and closes the least recently used
  idle one, which may be a rendezvous node's; the node then drops the
  membership, with its offers. The client's next announce joins anew under a
  new member id, which makes it drop its earlier offers at once rather than
  hold their places for their lifetime. Only that announce connects again:
  in the discovery turn, which it lets go before it waits on the node, like a
  room's lookup; an answer or a leave on a session that has closed fails at
  once, since the node has dropped the membership it belonged to.

## Consequences

### Positive

- The close group serves a popular file about once per swarm rather than once
  per reader. In the native end-to-end test the second reader of an 8 MiB file
  took every record from the first, and the nodes received no GET for any of
  them (`ant-core/tests/e2e_swarm.rs`).
- No new service and no third party: the readers' own nodes introduce them, on
  connections they already have.
- A peer cannot corrupt a read, and a bad or slow peer costs one short wait.

### Negative / Trade-offs

- **Readers of a file learn each other's addresses.** That is how
  BitTorrent works, and it is new here: until now only nodes saw a reader's
  address. A browser hides its local addresses behind mDNS names; a native
  client's offer lists its host addresses. The rendezvous nodes learn which
  connections read which file; a reader's close-group nodes could already see
  the records it fetches.
- **Private files too.** Two readers of the same private DataMap now meet; the
  room key, a hash of the root map, does not reveal the map or the content.
  Self-encryption is convergent, so the same content stored privately and
  publicly has the same root map and records, and its private and public
  readers meet in one room; its nodes could already see them fetch the same
  records.
- **Clients upload.** A client sends up to 4 records at once to other readers
  for as long as it is in their room, which costs bandwidth and, on phones,
  data and battery.
- **Browsers poll.** A browser's announce every 1 to 3 s per room and
  rendezvous node is a small request on its control lane; a held announce
  would cost it a request slot instead. Native clients long-poll. A room of
  a few hundred browsers can fill a node's swarm budget; its members are
  then refused and back off, which slows their meeting but never their reads.
- **Nodes browsers cannot reach host no rooms**, so a network of nodes built
  without the browser listener has no swarm, natively either.
- **Native clients link webrtc-rs**, which compiles in rustls's ring provider
  alongside aws-lc-rs. rustls then cannot pick a process-wide provider by
  itself, so the client installs aws-lc-rs, the one QUIC uses, before its
  first peer connection, as saorsa-transport already does for nodes.
- **Two readers on different networks may not connect** when both NATs are
  symmetric: there is no relay, by design. They read from the nodes.
- **Native readers behind relays get no STUN.** A client uses a node's STUN
  servers only at an address it reached that node on. A native client whose
  connection to a rendezvous node runs through a relay reached the relay,
  not the node's WebRTC Direct address, so it uses none of that node's STUN
  servers, and on a network reached at public addresses its host candidates
  are dropped too. Two such native readers behind NATs then exchange offers
  but cannot link, and read from the nodes. Browsers reach nodes directly
  and are not affected. Open: whether a client may check a node's direct
  address before trusting its STUN servers, or should prefer a directly
  reached rendezvous node.
- **A request taken after its connection closed.** A node can take a native
  request its transport queued before the connection closed, after the
  close; such a membership, like any a client stops using without leaving,
  stays at most 60 s of silence. Tying requests to the connection they came
  on needs saorsa-core to tag packets with their connection; it does not.
- **Hidden tabs.** A hidden browser tab reads from the nodes, not peers, and
  still serves. Its 20 s send bound runs on timers the browser slows in a
  hidden tab (to about a minute at worst), so a peer that stops reading can
  hold one of its 4 upload turns that long; stopping uploads when hidden
  would end background seeding.

### Neutral / Operational

- Nodes count announces, refusals, offers delivered and undelivered, answers
  delivered and unmatched (`SwarmService::counters`); clients report
  `SwarmStats` (records and bytes from and to peers, rejected records, links,
  rooms).
- Rollout order does not matter for correctness. Nodes first lets new clients
  share at once; clients first costs native clients the backed-off timeouts
  above until their rooms' nodes upgrade.

## Validation

- ant-protocol: the variants' discriminants are pinned, and a swarm announce
  round-trips; the limits are tested at their bounds.
- saorsa-transport: plain Binding answers carry the source address (IPv4-mapped
  sources as IPv4), check and return FINGERPRINT, leave connectivity checks and
  other packets to the usual handling, drop refused plain requests, are
  answered only for allowed sources within their rate, share one rate per IPv6
  /64, and stop at the socket's overall budget.
- saorsa-core: a send on a named connection is refused for a connection that
  is not the peer's, and never falls back or dials.
- ant-node: unit tests for requests naming another node, introductions, answers nobody asked for, long-poll
  wake-up and shutdown, caps and leaving, expiry, the STUN allowlist, request
  classification from the header, the unanswered-offer cap, browsers never
  waiting, one waiting announce per member, a signal already taken not cutting
  a later wait short, requests from before a close joining nothing,
  replayed or stale native requests, histories started only by announces and
  leaves and capped per host, ended memberships refused however late their
  announce, kept per connection and host, members capped per host, and a departing member's signals
  and the offers made to it going with it.
- ant-client unit tests over an in-memory WebRTC stand-in: a record served to
  a second and a third client, nothing asked for a record nobody announced, a
  forged record and out-of-order pieces ending the link, a stalled peer costing
  one stall and being sent `Cancel`, a dribbling peer running out of time,
  `Missing` and `Busy` falling back at once, crossing links settling on one,
  the per-link send limit, reads taking turns on one link, a record of another
  room neither announced nor served, a full queue closing the channel, and
  shutdown.
- ant-client end to end, native, on in-process nodes with real webrtc-rs: a
  second reader served records by the first, the nodes asked for every record
  it did not send, a reader whose peer left served by the nodes, and readers of
  different files not meeting. (The race itself, a peer keeping a read or the
  nodes taking it, is timed by unit tests on a paused clock.)
- ant-client end to end in real Chromium (`browser-tests/swarm.spec.js`): two
  pages in separate contexts read one file; with nodes that host rooms, the
  second takes data records from the first (CI runs this against the ant-node
  the client is built with); with the pinned older node CI also runs,
  it reads from the nodes and no swarm message is sent.
- A native client and Chromium pages in one room, on a local devnet: a page
  took every data record from a native client (webrtc-rs), and a native client
  every data record from a page, in 4 of 5 runs; in the other one record ran
  out of time and came from the nodes.
- The browsers installed on the machine, started by the operating system
  rather than a test driver: Brave took every data record from Chrome in 3 of
  3 runs. Firefox could not be checked locally: the local nodes listen only on
  loopback, which Firefox does not use for WebRTC.
- Review triggers: a record from a peer ever reaching a caller unchecked, or
  answering an existence check; a node limit that has to grow; the STUN answer
  growing relative to the request.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
