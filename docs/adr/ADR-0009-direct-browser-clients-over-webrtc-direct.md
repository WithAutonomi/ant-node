# ADR-0009: Direct browser clients over WebRTC Direct

- **Status:** Proposed
- **Date:** 2026-08-03
- **Last amended:** 2026-08-25
- **Decision owners:** <pending>
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** [W3C WebRTC](https://www.w3.org/TR/webrtc/),
  [WebRTC Data Channels](https://www.rfc-editor.org/rfc/rfc8831),
  [libp2p WebRTC Direct](https://github.com/libp2p/specs/blob/master/webrtc/webrtc-direct.md),
  [W3C WebTransport](https://www.w3.org/TR/webtransport/),
  [WebTransport over HTTP/3](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/)

## Context

Web applications must be able to act as full immutable-data clients: they
perform iterative closest-node lookup, download chunks, obtain and verify
storage quotes, pay, and upload chunks themselves. A node must not perform a
whole-network lookup, proxy chunk bytes, or hold a browser user's wallet key.
Ordinary bootstrap peers and end-to-end transport relays remain allowed;
application gateways do not.

The native node endpoint cannot be used by an unmodified browser. It speaks a
Saorsa-specific QUIC application protocol with ML-KEM/ML-DSA raw-public-key
authentication. Browsers do not expose arbitrary UDP or arbitrary QUIC. They
expose browser-controlled transports such as WebRTC and WebTransport, with
authentication and connection-establishment rules that applications cannot
bypass.

Nodes must remain easy to deploy. An operator must not need to acquire or
maintain a DNS name, obtain a public-CA certificate, or configure a signaling
service. Node software must generate and persist any browser-transport
credentials automatically.

Cold bootstrap must also remain decentralized and durable. A web client must
be able to start from a compiled-in list of self-contained, constant
multiaddresses even when that list or the installed web application is months
old. Loading a fresh bootstrap manifest over HTTPS must not be a prerequisite.
A bootstrap address may become unusable because the seed was retired or its
IP, port, or ANT identity actually changed, but it must not expire merely
because a browser transport routinely rotated a short-lived certificate.
Applications therefore ship several independent bootstrap addresses and may
revise them in later releases, but normal certificate maintenance must not
force such a release.

Many ordinary storage nodes also run behind NAT. Browser support must
distinguish an application gateway, which is rejected, from a transport relay
that forwards end-to-end encrypted traffic and is sometimes unavoidable on
the public Internet. The constant bootstrap set itself consists of stable,
publicly reachable seeds; NATed nodes are learned after bootstrap and use
direct ICE where possible or an end-to-end relay path.

This ADR records the intended production architecture and distinguishes it
from the repository's earlier, explicitly non-production WebTransport proof
of concept. That proof validated browser interoperability, request framing,
local DHT access, chunk downloads, and paid immutable uploads. It also exposed
the bootstrap-lifetime problem that caused the production transport decision
to be reconsidered.

## Decision Drivers

- Browsers perform Kademlia iteration and chunk integrity verification.
- Chunk data flows between the browser and the storing node, never through an
  application-level lookup/download gateway.
- A browser can cold-bootstrap from a compiled-in list of constant,
  self-contained multiaddresses without first fetching fresh configuration.
- Bootstrap addresses remain usable across routine node restarts and for
  substantially longer than one month; they do not contain routinely rotating
  certificate pins.
- Operators do not obtain or manage DNS names, public-CA certificates, or a
  node-specific signaling service.
- Browser transport keys and certificates are created and persisted by the
  node software without operator involvement.
- The existing post-quantum node-to-node port and wire protocols remain
  unchanged.
- A public browser protocol is narrow, versioned, bounded, and limited to
  immutable reads plus quote/payment-verified immutable writes.
- Wallet secrets remain inside the browser; nodes receive only normal signed
  quote artifacts, transaction hashes, and encrypted records.
- NATed nodes have an end-to-end direct or relay path without exposing
  plaintext to a signaling or relay peer.
- A 4 MiB chunk is transferred reliably with explicit fragmentation,
  backpressure, cancellation, and bounded buffering.
- Endpoint ownership remains bound to the node's persistent ML-DSA identity
  even though browser DTLS currently uses classical cryptography.

## Considered Options

1. **Expose the existing Saorsa QUIC endpoint.** Rejected because browser
   JavaScript cannot create an arbitrary QUIC connection or configure the
   current PQ raw-public-key handshake.
2. **Use HTTP/WebSocket gateways.** Rejected as the production architecture
   because the gateway would perform lookup or carry chunk data for the
   browser. It creates availability, bandwidth, privacy, and censorship
   chokepoints.
3. **Use WebSocket or WebTransport with Web PKI.** A DNS multiaddress and
   ordinary CA certificate can remain constant while certificates renew
   behind the hostname. This gives WebTransport an excellent byte-stream API,
   but it makes every browser-capable node depend on DNS and CA automation and
   therefore violates the deployment requirement.
4. **Use hash-pinned WebTransport with self-signed certificates.** This was the
   original choice and was the transport used by the repository's superseded
   PoC.
   WebTransport request/response streams, QUIC flow control, and cancellation
   fit 4 MiB chunk transfers well. It also needs no DNS or public CA. However,
   WebTransport limits hash-pinned certificates to a two-week validity period.
   Even with overlapping current and next pins, a month-old bootstrap
   multiaddress normally contains only retired pins. A client cannot learn the
   replacements through DHT iteration until one initial connection succeeds.
   Fetching a fresh HTTPS manifest would move bootstrap liveness to a separate
   WebPKI service and violate the constant-list requirement. This option is
   rejected as the production bootstrap and direct-node transport.
5. **Use ordinary signaled WebRTC.** WebRTC provides mature ICE/STUN/TURN NAT
   traversal and does not require the remote DTLS certificate to chain to a
   public CA. Conventional WebRTC nevertheless requires an out-of-band path to
   exchange SDP, ICE candidates, credentials, and certificate fingerprints
   for every connection. Making HTTPS or WebSocket signaling mandatory would
   introduce the DNS, CA, and signaling dependencies this decision excludes.
   Signaled WebRTC remains useful for connections to NATed nodes after the
   browser has already joined the network.
6. **Use libp2p WebRTC Direct.** This proves signaling-free
   browser-to-public-node WebRTC is practical, but it also adds a second peer
   identity, Noise, multistream negotiation, stream emulation, connection
   gating, and libp2p's mux lifecycle on top of DTLS/SCTP. Those layers are not
   used by the ANT RPC protocol, which already authenticates the persistent
   ML-DSA node identity. During the PoC, current JavaScript and Rust libp2p
   releases also disagreed about DataChannel close control (`FIN_ACK`), causing
   later RPCs on an otherwise healthy association to fail with unexpected EOF.
   Carrying vendored compatibility patches for an unnecessary wire stack is
   rejected.
7. **Use a Saorsa-owned WebRTC Direct profile (chosen).** A browser dials a
   public IP and UDP port
   directly, constructs the peer descriptions locally, and establishes an
   ICE-lite + DTLS + SCTP association without a signaling server. The
   multiaddress contains a stable DTLS certificate fingerprint and the
   expected ANT peer ID. Unlike WebTransport's hash-pinned certificate, the
   remote WebRTC certificate is authenticated by its SDP fingerprint and does
   not need routine two-week rotation. The trade-off is a more complex stack
   and a message-oriented DataChannel API that needs bounded application
   framing. Saorsa owns the listener, UDP/ICE association routing, certificate
   lifecycle, endpoint API, and DataChannel profile while using standard
   WebRTC protocol primitives, just as its QUIC implementation owns the
   transport while using audited cryptographic primitives.
8. **Use WebRTC Direct only for bootstrap and WebTransport for data.** This
   would combine stable bootstrap with WebTransport's superior byte streams.
   It is not the initial production choice because every browser-capable node
   would need two browser transports, two endpoint forms, and two independent
   compatibility and resource-control surfaces. It can be reconsidered if
   measured DataChannel performance is inadequate for 4 MiB chunks.

## Decision

We will add a separate WebRTC Direct listener to browser-capable nodes. It is
included and enabled in standard node builds so an ordinary deployment is
browser reachable without deployment-specific flags; custom configuration can
disable it, and minimal native-only builds can omit the default feature.
Browser clients will use it to connect directly, perform one-hop
`FIND_NODE` RPCs iteratively, download chunks with `GET_CHUNK`, and store paid
chunks with the same quote and payment checks as native clients.

The initial transport targets browser-to-public-server WebRTC Direct. It uses
ICE-lite on the node, browser-managed ICE on the client, DTLS for transport
confidentiality and integrity, reliable ordered SCTP DataChannels, and a
mandatory application-layer ML-DSA identity handshake. It does not require a
DNS name, public-CA certificate, TURN server, or out-of-band SDP signaling for
a directly reachable node.

The transport is implemented and versioned by Saorsa. It does not use libp2p
libraries or wire layers: there is no libp2p peer ID, Noise handshake,
multistream selection, connection gater, protobuf stream envelope, or libp2p
DataChannel close protocol. `saorsa-transport` owns ICE-lite/DTLS/SCTP setup,
the shared UDP association mux, persisted certificates, native diagnostic
dialing, and reliable ordered DataChannels. `saorsa-core` owns only the
validated endpoint/address integration. `ant-node` owns the bounded browser
RPC protocol, and browser clients use `RTCPeerConnection` directly.

The native ML-KEM/ML-DSA transport remains the node-to-node transport and is
not downgraded or replaced. The WebRTC listener has independent connection,
channel, request, timeout, message, and byte limits. Its write surface accepts
only content-addressed chunks accompanied by a verifiable native payment
proof.

### Stable addresses and transport certificates

The canonical direct address form is:

```text
/ip4/<address>/udp/<port>/webrtc-direct
  /certhash/<stable-sha2-256-multihash>
  /p2p/<ant-peer-id>
```

`ip6` is also valid. Constant bootstrap addresses use literal IP addresses;
DNS is neither required nor used as an authentication mechanism. Certificate
multihashes use unpadded base64url multibase (`u`) and contain exactly a
32-byte SHA-256 digest.

The `/certhash` component is required by WebRTC Direct so the browser can
construct and authenticate the remote DTLS description. It is deliberately a
stable fingerprint, not a temporary WebTransport-style pin. On first startup,
the node generates a P-256 DTLS certificate and stores it beside its persistent
node identity. The certificate has a long validity window and restarts reuse
the same DER bytes, key, and fingerprint. A deterministic, domain-separated
derivation from persistent node key material may be adopted only after
cryptographic review; persistence is the default design. Stable WebRTC Direct
fingerprints across restarts have also been implemented as
[libp2p prior art](https://github.com/libp2p/go-libp2p/pull/3512).

The DTLS transport key is not the ANT identity credential. Compromise of that
key alone must not authorize browser RPCs. Before accepting application
requests, the node proves possession of its ML-DSA identity key in a
domain-separated handshake covering at least the network ID, protocol version,
fresh browser challenge, expected peer ID, and advertised DTLS fingerprint. The
browser verifies the public-key-to-peer-ID binding and the signature. A
mismatched `/p2p` identity aborts the connection.

Routine time-based DTLS certificate rotation is not performed. Rotation is an
exceptional operation associated with transport-key compromise or node
identity replacement and produces a new multiaddress. Designated bootstrap
operators must then retain overlap in the compiled bootstrap set across client
releases. This is equivalent to changing a bootstrap peer's ANT identity, not
ordinary certificate maintenance.

An IP address and port can still change. Constant bootstrap nodes therefore
require stable public addressing and long-lived ANT identities, and clients
ship multiple independently operated seeds. Ordinary nodes are not required
to have stable addresses; their current signed records are learned through the
network.

### Bootstrap and endpoint discovery

The web client contains a constant list of bootstrap `MultiAddr` values. These
entries are trust anchors and have no routine time-based expiry. The list is
sufficient to initiate DHT lookup without fetching a manifest, resolving DNS,
or contacting an application service. A newer application release may add or
retire seeds, but bootstrap does not depend on receiving that release.

The implemented discovery path has two wire-compatible generations backed by
one canonical in-memory address set. The existing Postcard
`PublishAddressSet` operation is frozen: it retains the original closed
`AddressType` enum and carries only the `Quic` projection. Neither WebRTC nor
any future transport is added to that enum or legacy `FIND_NODE` response.

The new address plane uses a separate `/dht/address/2.0.0` topic and complete
replacement records:

```text
PublishAddressSetV2 {
    seq: u64,
    records: [TransportAddressRecord]
}

TransportAddressRecord {
    transport: u16,
    reachability: u16,
    address: bytes
}
```

Known transport identifiers are `Quic = 1` and `WebRtcDirect = 2`. Transport
and reachability are deliberately orthogonal: the known reachability IDs are
Relay, Direct, Unverified, and Lan, and a WebRTC Direct listener is initially
published as `WebRtcDirect + Unverified`. Relay acquisition selects
`Quic + Direct`; native dialing never consumes WebRTC records.

The identifiers are numeric fields rather than serialized Rust enums and are
never reused. `address` is a bounded, length-delimited payload that is decoded
only after recognizing `transport`. Consequently a V2-aware node can decode,
retain, and forward an unknown future transport or reachability value without
understanding or dialing it. Known records must decode to a multiaddress whose
transport matches the declared identifier; WebRTC records must also contain
the authenticated owner's peer ID.

V2 also defines a matching `FindNodeV2` result carrying complete transport
records. This keeps extension addresses out of the legacy `DHTNode` shape while
allowing sequence-bearing DHT gossip to distribute WebRTC endpoints beyond the
direct recipients of a publish.

Support is advertised by the `addr-v2` capability in the signed identity user
agent. During migration, a new node sends V2 publish and lookup operations to
capable peers and the unchanged V1 operations to older peers. Thus new-to-old
and old-to-new links continue to propagate QUIC addresses, while WebRTC and
future records flow only between upgraded nodes. The V2 topic is separate, so
an old node also ignores an accidentally delivered V2 frame instead of trying
to deserialize an unknown operation.

Reachability classification, relay acquisition, relay loss, and rebinding
mutate the one canonical address set and derive both wire projections from it;
V1 and V2 are not independent sources of truth. Once the network's minimum
supported version guarantees V2, nodes may stop publishing V1. Relay
acquisition continues through the `Quic + Direct` V2 records. Removing V1 is
an explicit compatibility cutoff: pre-V2 nodes will no longer discover or
join that network, and V1 decoding may be removed in a later cleanup release.

The browser accepts a discovered endpoint only when its `/p2p` suffix matches
the returned peer, then proves that binding again through certificate-pinned
DTLS and ML-DSA HELLO. A malicious DHT responder can omit an endpoint or make a
client spend a bounded failed dial, but cannot authenticate an endpoint as
another peer.

A later hardening phase may add a separately versioned, independently
cacheable record without changing the existing Postcard `DHTNode` shape:

```text
BrowserEndpointRecord {
    network_id,
    peer_id,
    sequence,
    expires_at,
    webrtc_multiaddrs,
    capabilities,
    protocol_versions,
    max_chunk_size,
    node_public_key,
    ml_dsa_signature
}
```

Such independently cacheable records would expire because IP addresses, ports,
relay allocations, and capabilities can change. That expiry would not apply to
the separately configured bootstrap trust anchors and would not be driven by
routine DTLS certificate rotation.

For that optional record, the ML-DSA signature covers a canonical,
domain-separated encoding. The browser would verify the public-key-to-peer-ID
binding, signature, network ID, monotonic sequence, expiry, capabilities, and
the entire multiaddress before dialing. An address received through an
unauthenticated channel is not made trustworthy merely by containing a
certificate hash.

The multiaddress is the complete dialing input: no separate IP address,
certificate fingerprint, or peer-ID argument is accepted by the browser
client. This prevents those values from being accidentally mixed between
nodes.

The address is represented by the network's native address types rather than
an application-owned string. `saorsa-transport` will own a validated WebRTC
Direct transport component, and `saorsa-core::MultiAddr` will own the
`/p2p/<ant-peer-id>` suffix. Canonical formatting, parsing, and string-based
Serde are the single Rust codec used by endpoint records, bootstrap lists,
`HELLO`, and `FIND_NODE`. `ant-node` must not maintain a second WebRTC Direct
multiaddress or certificate-hash codec.

The native Saorsa QUIC dialer deliberately does not treat a WebRTC Direct
address as a native QUIC dialing candidate. It is a first-class advertised
transport address whose browser stack remains separate from the PQ
node-to-node transport.

For deployment smoke tests, a browser-enabled node also writes its own
canonical address to `<root-dir>/webrtc-direct.multiaddr`. Deployment tooling
may print or copy this public artifact so an operator can paste one seed into
the browser demo without scraping structured logs or running a manifest
service. This is an operability aid, not the endpoint-discovery protocol; peer
endpoints propagate through DHT address sets.

With no explicit listener configuration, the node binds IPv4 wildcard and
maps its native UDP port deterministically into UDP 32768-65535. It advertises
the same-family non-relay external IP observed by the native transport, or the
host routing table's selected IP when no observation is available yet. The
automatic port and persisted certificate make the resulting multiaddress
stable across routine restarts. Explicit bind and advertised addresses remain
available for multi-homed and otherwise unusual deployments.

### WebRTC Direct interoperability status

The signaling-free connection mechanism has prior art in the [libp2p WebRTC
Direct v1 design](https://github.com/libp2p/specs/blob/master/webrtc/webrtc-direct.md):
the browser and public ICE-lite listener derive the descriptions locally, and
the first STUN binding request gives the listener the browser's observed
address and per-association ICE credential. Saorsa uses that standards-based
mechanism as design input, not the libp2p transport, identity, Noise, mux, or
stream wire protocols.

The current Saorsa profile is identified by the ICE credential prefix
`saorsa+webrtc+v1/`. Like the prior v1 mechanism, it replaces the ICE ufrag and
password in the browser-generated local SDP. Browser vendors are restricting
that unsupported SDP-munging behavior, creating a documented [Chrome
compatibility risk](https://github.com/libp2p/go-libp2p/issues/3499). Ongoing
[WebRTC Direct v2 work](https://github.com/libp2p/specs/pull/715) is useful
interoperability research because it avoids that mutation, but Saorsa does not
depend on libp2p adopting or shipping it.

Production is therefore conditional on a new, explicitly versioned Saorsa
connection-establishment profile that works without forbidden SDP mutation.
We should adopt compatible standards-level techniques and cross-browser test
vectors from v2 work where they fit. The ANT ML-DSA handshake remains the only
node-identity protocol. Unknown connection-establishment versions are rejected,
and v1 is not a silent fallback once browsers no longer support it.

### Browser protocol and DataChannel framing

The public protocol is not the private Saorsa `WireMessage` or native Postcard
DHT protocol. The initial methods are:

- `HELLO`: negotiate version/network/capabilities and complete node identity
  authentication.
- `FIND_NODE`: return up to the local DHT K value, ordered by XOR distance.
  It never initiates a network lookup on the server.
- `GET_CHUNK`: return a locally stored chunk, `not_found`, or a bounded error.
- `QUOTE_CHUNK`: return the node's ordinary ML-DSA-signed storage quote and,
  when present, its commitment sidecar. The browser verifies peer binding,
  quote signature, forced price, commitment signature, and commitment pin
  before paying. Its canonical signed fields use the native byte encoding;
  the EVM-facing `PaymentQuote::hash()` is Keccak-256 over those bytes followed
  by the public key and signature. This must not be confused with the BLAKE3
  hashes used for ANT identities, content addresses, and commitment pins.
- `PUT_CHUNK`: accept raw chunk bytes, the previously verified signed quote,
  and the payment transaction hash. The listener reconstructs the native
  single-node `PaymentProof` and routes the request through the ordinary PUT
  handler, including content-address and on-chain payment verification.
- `PING`: optional liveness method after the proof of concept.

WebRTC DataChannels are messages, not byte streams. One persistent reliable
ordered DataChannel carries a sequence of RPC request/response frames for one
association. The application framing is a four-byte JSON-header length, a
bounded versioned JSON header, and the declared raw binary body; chunk bytes
are never JSON/base64. Application frames are fragmented into DataChannel
messages of at most 16 KiB and reassembled directly by the receiver. No
libp2p stream envelope or half-close control frame exists.

Application frames are self-delimiting: receivers validate the JSON header and
its declared body length rather than trusting DataChannel boundaries. A client
serializes requests on its persistent channel, waits for the complete declared
response, and can then send the next request without closing the channel.
Trailing bytes, channel closure before completion, and mismatched lengths are
protocol errors. This design directly removes the cross-version `FIN_ACK` and
RESET lifecycle failure observed with the libp2p PoC.

High-level browser operations share a bounded pool of authenticated node
associations. Iterative lookups, quote collection, paid storage, and downloads
reuse the existing DataChannel for a node instead of creating a new
`RTCPeerConnection` for every encrypted record. This is both a performance and
compatibility requirement: the Safari PoC observed later DataChannels timing
out after rapid connection churn even though each earlier caller invoked
`close()`. The pool avoids relying on prompt browser resource reclamation,
serializes concurrent RPCs per node, limits live associations, evicts only idle
entries, and closes every entry when the complete file operation finishes.

The sender observes `bufferedAmount`, pauses above the configured high-water
mark, and resumes only after `bufferedamountlow`. Both sides cap total buffered
bytes, validate declared lengths before allocation, support cancellation by
closing the logical RPC channel, and reject bodies that exceed the method
limit. Both sides recompute BLAKE3 and reject content whose hash does not equal
its address.

Browser sessions are not inserted into node routing tables. Wallet secrets,
replication controls, arbitrary topic forwarding, and native DHT messages are
not exposed. Payment happens against the public EVM RPC and contracts: the
browser signs locally, and only the resulting public proof crosses WebRTC.

### Lookup behavior

The browser owns the iterative lookup state machine. It starts from the
constant WebRTC Direct bootstrap list, queries up to `ALPHA = 3` unqueried
closest endpoints in parallel, merges verified endpoint records, and stops at
convergence or the iteration limit. The initial implementation targets the
current native `K = 20` behavior. Lookup and chunk retry policies should
eventually share language-independent test vectors with the native client.

Every storage node, or a sufficient storage-aware replica set, must expose a
browser endpoint. Filtering native closest results to a sparse browser-only
subset is not considered equivalent to finding the network's actual closest
storage nodes.

### NAT and relays

WebRTC Direct removes the signaling server only for publicly reachable
listeners. It does not make a NATed server directly dialable from a static
address. After initial bootstrap, the browser can use authenticated network
peers to exchange short-lived SDP/ICE information with a NATed node. ICE tries
host and server-reflexive candidates first and uses an end-to-end relay
candidate when required.

Signaling peers coordinate connection establishment only. They do not perform
DHT lookup on the browser's behalf and do not carry application requests or
chunk bytes. A TURN-like or Saorsa relay forwards encrypted DTLS packets; DTLS
and application identity authentication terminate at the storage node, not
the relay. Relay allocations are published in signed, expiring endpoint
records rather than the constant bootstrap list.

### Implemented proof-of-concept slice

The earlier feature-gated WebTransport PoC has been replaced by the
`webrtc-direct` feature. The current slice provides:

- a separate Saorsa-owned WebRTC Direct UDP listener in `saorsa-transport` and
  a browser dialer built directly on `RTCPeerConnection`/`RTCDataChannel`;
- credential-first STUN routing in the shared UDP mux, so a new association is
  not sent to a stale ICE agent when a browser reuses a source UDP port;
- a generated and persisted DTLS certificate whose fingerprint remains stable
  across restarts;
- native `saorsa-transport` and `saorsa-core::MultiAddr` support for canonical,
  literal-IP `/webrtc-direct/certhash/.../p2p/...` addresses with exactly one
  fingerprint and no DNS form;
- a per-connection ML-DSA `HELLO` challenge before other RPCs. The signed
  transcript binds the challenge, ANT peer ID, and full advertised endpoint;
  the browser verifies both the signature and the public-key-to-peer-ID hash;
- a persistent reliable ordered application DataChannel, bounded 16-KiB
  messages, declared-length reassembly, and browser `bufferedAmount`
  backpressure;
- a bounded browser connection pool that reuses authenticated DataChannels
  across every lookup, quote, and record in one complete upload or download;
- a Rust/WASM random-access reader that resolves the public root DataMap,
  retrieves only encrypted records overlapping the requested plaintext byte
  range, and retains a bounded record cache for read-ahead and seeks;
- a same-origin service-worker adapter that exposes those verified ranges to a
  native browser media element with standard HTTP range semantics, without
  proxying bytes through a bootstrap or application server; and
- the existing local `FIND_NODE`, `GET_CHUNK`, `QUOTE_CHUNK`, and paid
  `PUT_CHUNK` behavior over the new transport.

The WebRTC primitive release currently used by the Rust implementation has a
known AES-256-GCM SRTP construction defect. The Saorsa setting engine therefore
advertises the interoperable AES-128-GCM and AES-128-CM profiles and omits the
broken profile. There is no vendored library patch. The AES-256 profile should
be restored only after upgrading the primitive and adding a regression test.

Literal private and loopback IPs require no library connection-gater exception
because the browser client does not run libp2p. Address parsing still requires
a literal IP, UDP, `/webrtc-direct`, exactly one SHA-256 certificate pin, and
the expected ANT peer ID before constructing an `RTCPeerConnection`.

The local manifest remains test scaffolding for ephemeral loopback ports. The
production client is designed to accept the same endpoint values from a
compiled constant list, without fetching a manifest or resolving DNS.

This implementation currently uses the Saorsa v1 connection-establishment
profile described above. It is a PoC, not evidence that the production
no-mutation gate has been met. Promotion remains blocked on the cross-browser
validation listed below.

### Local testnet implementation slice

The in-process `ant-devnet` launcher can enable a listener on every node. The
listeners share an in-memory endpoint catalog, allowing each local
`FIND_NODE` answer to attach the self-contained WebRTC Direct multiaddress of
every browser-enabled peer in its routing view. This catalog is explicitly a
local replacement for future signed DHT endpoint records, not a production
discovery mechanism.

Local testnets may publish a runtime manifest because their loopback addresses
and ephemeral ports are created for each test run. Production bootstrap must
not depend on that mechanism. A local manifest may expose bootstrap
multiaddresses, public-file metadata, public EVM RPC and contract addresses,
and a resolved public root DataMap; it never performs lookup or carries file
bytes and never includes wallet secrets.

At startup the launcher uses `self_encryption 0.36` to produce encrypted file
chunks and the same public MessagePack `DataMap` used by `ant-client`. It
publishes every record through each candidate node's ordinary PUT handler. It
pre-populates the devnet payment cache for those addresses, while
content-address verification, DHT responsibility, payment-cache admission,
LMDB storage, and verified reads remain active.

### Public Internet smoke result

On 2026-08-27 a headless Chromium client loaded the local web application and
dialed a literal public-IPv4 WebRTC Direct address on a DigitalOcean-hosted
node. With no browser manifest available, it completed ICE, DTLS, SCTP, the
DataChannel handshake, and authenticated ML-DSA `HELLO`; the UI then installed
that single address as the Rust network bootstrap seed and completed a
`FIND_NODE` query without page errors. Restarting the remote node left the
complete multiaddress byte-identical and the same browser client reconnected
using the pre-restart value.

The result was repeated with the unchanged stock `ant-testnet` workflow after
WebRTC Direct became a default node feature. A normal 60-node deployment used
no browser-specific build, service, firewall, or advertised-address flags;
bootstrap node 0 automatically published its public IPv4 endpoint on the
derived UDP 42768 port.

Using the pre-V2 address-dissemination prototype, Chromium bootstrapped from
that one address, traversed routing views from dozens of independent peer
processes, obtained four quotes from four non-bootstrap closest nodes, paid
once, and stored all four encrypted records. This verifies that the input
address is a bootstrap seed rather than a storage proxy. Nodes behind the
testnet's deliberate inbound-NAT rules still require relayed WebRTC; failed
direct attempts are tolerated but currently add the full DataChannel opening
timeout to lookup latency.

After replacing that prototype with the compatibility-safe V2 address plane,
a five-node headless-Chromium test again started with exactly one WebRTC seed.
It discovered the remaining browser endpoints through `FindNodeV2`, paid for
and stored eight records across the network, read disjoint and suffix media
ranges, and downloaded the verified reconstruction. The V1/V2 wire migration
itself is additionally covered by legacy-decoder and unknown-identifier
round-trip tests.

## Consequences

### Positive

- A web client can bootstrap from months-old constant IP multiaddresses
  without DNS, Web PKI, a fresh manifest, or a signaling server.
- Routine node restarts and certificate maintenance do not change the
  advertised address.
- Operators do not manage DNS names or CA certificate issuance; node software
  creates and persists the browser transport credential.
- Browsers can become application-level full immutable-data clients without a
  lookup, payment, upload, or download gateway.
- Browser-supported videos can start and seek without downloading or
  reconstructing the complete file.
- WebRTC supplies a standardized browser API and an established path toward
  direct ICE and end-to-end relayed connectivity for NATed nodes.
- The stable DTLS fingerprint is separately bound to the persistent PQ node
  identity rather than being treated as the ANT identity.
- Rust producers and consumers share the network's native `MultiAddr` codec;
  browser JavaScript implements the same canonical wire syntax.
- Existing PQ node networking and compatibility remain isolated.

### Negative / Trade-offs

- Browser-capable nodes run a second UDP listener and an ICE-lite + DTLS + SCTP
  stack in addition to native QUIC.
- DataChannels require application fragmentation, reassembly, flow control,
  and cancellation. They are less natural than WebTransport streams for 4 MiB
  chunks.
- Native media playback needs a small same-origin service-worker bridge because
  a page-owned WebRTC client cannot itself expose an HTTP range URL. The page
  must remain open while playback uses its authenticated associations.
- A stable DTLS transport key has a larger compromise window. ML-DSA
  application authentication limits its authority, but emergency replacement
  of a bootstrap fingerprint still requires overlap and client-list updates.
- Constant bootstrap peers require stable public IP addresses and ports even
  though ordinary nodes do not.
- Signaling-free WebRTC Direct depends on browser behaviors beyond the basic
  WebRTC API. The v2 profile and Chrome, Firefox, and Safari interoperability
  must be proven before production.
- Direct operation still requires broad browser-endpoint coverage among
  storage nodes. NATed nodes may consume relay bandwidth even though relays
  cannot read their traffic.
- Current browser DTLS is not post-quantum.

### Neutral / Operational

- The official web application still needs a secure HTTPS context. Its web
  certificate is unrelated to node deployment and is not a bootstrap
  dependency after the application has been installed.
- Designated bootstrap nodes have stronger uptime and stable-address
  requirements than ordinary storage nodes.
- Origin is policy input, not client authentication. Public deployments still
  need per-IP/session request, channel, and byte quotas.
- Bootstrap peers do not perform lookup or proxy uploads/downloads; they
  answer the same bounded one-hop RPCs as other browser-capable nodes.

## Validation

The decision advances beyond PoC only after all of the following are covered:

- A browser bootstraps with networking disabled for manifest/DNS services and
  only the compiled literal-IP multiaddresses available.
- A bootstrap multiaddress and certificate fingerprint remain byte-identical
  across node restarts and simulated passage of at least one month.
- Documented recovery tests cover certificate compromise, deliberate identity
  rotation, one retired bootstrap seed, and overlap between old and new
  compiled seed lists.
- WebRTC Direct connection establishment works on current Chrome, Firefox,
  and Safari from a real secure context without forbidden SDP mutation. Tests
  explicitly cover the Chrome ICE-credential restriction that breaks v1.
- The browser rejects wrong fingerprints, wrong peer IDs, wrong networks,
  replayed handshakes, invalid ML-DSA signatures, and signatures not bound to
  the DTLS transcript.
- Automated tests cover malformed STUN/SDP/SCTP input, oversized messages,
  excessive channels, slow readers, connection floods, request amplification,
  and global/per-client byte quotas.
- UDP-mux regression tests cover source-port reuse: a binding request carrying
  a new ICE credential must override a stale address mapping, while binding
  responses and non-STUN traffic continue to use the selected address mapping.
- Browser-side iterative lookup parity tests cover XOR ordering, `K`, `ALPHA`,
  convergence, retries, expired discovered records, and unavailable endpoints.
- Reliable downloads and uploads work at 0 bytes, typical sizes, and 4 MiB,
  with BLAKE3 verification, bounded memory, fragmentation, cancellation, and
  backpressure measurements.
- Media tests cover disjoint, open-ended, and suffix byte ranges, seeks across
  self-encryption chunk boundaries, nested DataMaps, bounded cache behavior,
  invalid/multiple ranges, cancellation, and exact reconstructed bytes.
- Multi-record uploads and concurrent downloads remain within the browser
  connection-pool bound and complete on Safari without accumulating closed
  `RTCPeerConnection` instances.
- Paid-upload tests cover quote/commitment tampering, wrong peers, wrong
  content, missing/failed payments, replay/idempotence, wallet rejection, and
  successful native-client retrieval of browser-created files.
- A fleet test demonstrates that browser endpoint coverage reaches the storage
  nodes selected by native closest-group rules.
- NAT traversal tests measure direct ICE success and exercise an end-to-end
  relay path where DTLS terminates at the NATed node, not the relay.
- Regression tests prove the existing native PQ port and native client
  behavior are unchanged when browser support is disabled.
- WebRTC and the recorded WebTransport baseline are benchmarked for setup
  latency, CPU and memory, sustained 4 MiB throughput, cancellation, loss
  recovery, and concurrent request behavior before production promotion.
- Review triggers fire when WebRTC Direct v2, browser SDP enforcement, SCTP
  DataChannel behavior, node storage placement, or Saorsa relay APIs change
  materially.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human
review**. Accepted ADRs are immutable: create a new superseding ADR rather than
editing an Accepted ADR.
