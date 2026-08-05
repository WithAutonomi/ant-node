# ADR-0009: Direct browser clients over WebTransport

- **Status:** Proposed
- **Date:** 2026-08-03
- **Last amended:** 2026-08-05
- **Decision owners:** <pending>
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** [W3C WebTransport](https://www.w3.org/TR/webtransport/),
  [WebTransport over HTTP/3](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/),
  [W3C WebRTC](https://www.w3.org/TR/webrtc/)

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
expose WebTransport sessions negotiated through HTTP/3 or HTTP/2 and require
browser-compatible TLS authentication.

Many nodes also run behind NAT. Browser support must distinguish an
application gateway, which is rejected, from a transport relay that forwards
end-to-end encrypted datagrams and is sometimes unavoidable on the public
Internet.

This ADR records the intended production architecture and defines a smaller,
explicitly non-production proof of concept. The proof of concept validates
browser interoperability, request framing, local DHT access, chunk downloads,
and paid immutable uploads; signed endpoint dissemination and relayed
WebTransport are later implementation slices.

## Decision Drivers

- Browsers perform Kademlia iteration and chunk integrity verification.
- Chunk data flows between the browser and the storing node, never through an
  application-level lookup/download gateway.
- Operators must not need to obtain DNS names or public CA certificates.
- The existing post-quantum node-to-node port and wire protocols remain
  unchanged.
- A public browser protocol must be narrow, versioned, bounded, and limited to
  immutable reads plus quote/payment-verified immutable writes.
- Wallet secrets remain inside the browser; nodes receive only normal signed
  quote artifacts, transaction hashes, and encrypted records.
- NATed nodes need an end-to-end relay path without exposing plaintext to the
  relay.
- A 4 MiB chunk needs reliable streaming and backpressure.
- Endpoint ownership must remain bound to the node's persistent ML-DSA
  identity even though browser TLS currently uses classical cryptography.

## Considered Options

1. **Expose the existing Saorsa QUIC endpoint.** Rejected because browser
   JavaScript cannot create an arbitrary QUIC connection or configure the
   current PQ raw-public-key handshake.
2. **Use HTTP/WebSocket gateways.** Rejected as the production architecture
   because the gateway would perform lookup or carry chunk data for the
   browser. It creates availability, bandwidth, privacy, and censorship
   chokepoints.
3. **Make one UDP port detect both native QUIC and WebTransport.** Rejected for
   the first implementation. It mixes two TLS stacks, two QUIC protocol
   implementations, and different identity models in the most sensitive part
   of the node.
4. **Use WebRTC DataChannels.** Not selected as the primary transport.
   WebRTC's ICE/STUN/TURN support can establish direct paths through more NATs,
   and it does not require Web PKI. However, every peer connection needs an
   out-of-band SDP/ICE signaling exchange and a separate ICE + DTLS + SCTP
   stack. DataChannels also require application fragmentation and buffered
   amount management for 4 MiB chunks. WebRTC remains a candidate fallback if
   measured direct-ICE success justifies this complexity.
5. **Add a separate WebTransport listener to each node (chosen).** It maps
   directly to request/response streams, leaves native networking unchanged,
   and supports a pinned self-signed certificate without operator-managed
   Web PKI.

## Decision

We will add a separate, opt-in WebTransport-over-HTTP/3 listener to nodes.
Production browser-capable nodes will publish an owner-signed browser endpoint
record. Browser clients will use those records to connect directly, perform
one-hop `FIND_NODE` RPCs iteratively, download chunks with `GET_CHUNK`, and
store paid chunks with the same quote and payment checks as native clients.

### Transport and certificates

- WebTransport uses a separate UDP socket and port from native Saorsa QUIC.
- Node software generates P-256 X.509v3 certificates automatically. Operators
  do not obtain public CA certificates.
- Each node embeds the certificate's SHA-256 DER multihash in its advertised
  WebTransport multiaddress. Applications supply only the multiaddress; the
  browser client extracts the digest and passes it internally through
  `serverCertificateHashes`.
- Production nodes maintain overlapping current and next certificates because
  hash-pinned WebTransport certificates may be valid for at most two weeks.
- The listener has independent connection, stream, request, timeout, and byte
  limits. Its write surface accepts only content-addressed chunks accompanied
  by a verifiable native payment proof.
- The native ML-KEM/ML-DSA transport remains the node-to-node transport and is
  not downgraded or replaced.

### Endpoint discovery and identity

Production discovery uses a separately versioned record rather than changing
the existing Postcard `DHTNode` shape in place:

```text
BrowserEndpointRecord {
    network_id,
    peer_id,
    sequence,
    expires_at,
    webtransport_multiaddrs,
    capabilities,
    protocol_versions,
    max_chunk_size,
    node_public_key,
    ml_dsa_signature
}
```

The canonical direct address form is:

```text
/ip4/<address>/udp/<port>/quic-v1/webtransport
  /certhash/<current-sha2-256-multihash>
  [/certhash/<next-sha2-256-multihash>]
  /p2p/<ant-peer-id>
```

`ip6`, `dns`, `dns4`, and `dns6` host components are also valid. Certificate
multihashes use unpadded base64url multibase (`u`) and must contain exactly a
32-byte SHA-256 digest. Implementations accept at most the current and next
hash. The `/webtransport` component maps to the fixed
`/autonomi/webtransport/v1` HTTPS session path.

This is represented by the network's native address types rather than an
application-owned string. `saorsa-transport` stores the transport component as
`TransportAddr::WebTransport(WebTransportAddr)`, including the validated host,
port, and certificate hashes. `saorsa-core::MultiAddr` wraps that transport
component and owns the `/p2p/<ant-peer-id>` suffix. Its canonical `Display`,
`FromStr`, and string-based Serde implementations are the single Rust codec
used by endpoint records, manifests, `HELLO`, and `FIND_NODE`. `ant-node` must
not maintain a second WebTransport multiaddress parser or certificate-hash
codec.

The native Saorsa QUIC dialer deliberately does not treat a WebTransport
address as a native QUIC dialing candidate. It is a first-class advertised
transport address whose browser HTTP/3 stack remains separate from the PQ
node-to-node transport.

The multiaddress is the complete dialing input: no separate URL, certificate
hash, or peer-ID argument is accepted by the browser client. This prevents the
three values from being accidentally mixed between nodes. A certificate hash
authenticates the ephemeral TLS key, while `/p2p` identifies the expected
persistent ANT identity. The endpoint-record signature binds the whole address
to that identity. An address received through an unauthenticated channel is not
made trustworthy merely by containing a hash; initial bootstrap addresses are
application trust anchors, and discovered addresses require owner signatures.

During rotation, nodes advertise current and next hashes in the same address,
switch certificates only after the next hash has propagated, then replace the
retired hash with a newly generated next hash. Cached addresses must expire no
later than their last certificate. Rotation and address publication are node
software responsibilities, not operator or web-application configuration.

The ML-DSA signature covers a canonical, domain-separated encoding. The
browser verifies the public-key-to-peer-ID binding, signature, network ID,
sequence, expiry, capabilities, and certificate hash before connecting.
Initial bootstrap records are distributed with the HTTPS web application;
subsequent records are learned during DHT iteration.

The classical browser TLS certificate is therefore an ephemeral transport key
bound by an application-layer ML-DSA signature to the node's persistent PQ
identity. Browser TLS confidentiality is not post-quantum until browsers
standardize and expose a suitable PQ TLS mode.

### Browser protocol

The public protocol is not the private Saorsa `WireMessage` or native Postcard
DHT protocol. Each client-created bidirectional stream carries one request and
one response. The initial methods are:

- `HELLO`: negotiate version/network/capabilities and return node identity.
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

Requests and responses use a four-byte big-endian JSON-header length, a
bounded versioned JSON header, and an optional raw binary body. Chunk bytes are
never JSON/base64. Both sides recompute BLAKE3 and reject content whose hash
does not equal its address.

Browser sessions are not inserted into node routing tables. Wallet secrets,
replication controls, arbitrary topic forwarding, and native DHT messages are
not exposed. Payment happens against the public EVM RPC and contracts: the
browser signs locally, and only the resulting public proof crosses
WebTransport.

### Lookup behavior

The browser owns the iterative lookup state machine. It starts from ordinary
bootstrap nodes, queries up to `ALPHA = 3` unqueried closest endpoints in
parallel, merges verified endpoint records, and stops at convergence or the
iteration limit. The initial implementation targets the current native
`K = 20` behavior. Lookup and chunk retry policies should eventually share
language-independent test vectors with the native client.

Every storage node, or a sufficient storage-aware replica set, must expose a
browser endpoint. Filtering native closest results to a sparse browser-only
subset is not considered equivalent to finding the network's actual closest
storage nodes.

### NAT and relays

Publicly reachable nodes accept WebTransport directly. For NATed nodes,
Saorsa's relay layer will be generalized to provide a UDP forwarding socket
usable by the standard WebTransport QUIC implementation. The node publishes
the relay allocation as another signed WebTransport URL. TLS and application
traffic remain end-to-end between browser and storage node; the relay only
forwards encrypted datagrams.

WebRTC may be reconsidered as an optional path after an interoperability study
measures ICE setup latency, direct-connect success, TURN fallback, node
resource use, and 4 MiB DataChannel performance.

### Proof-of-concept slice

The repository PoC is intentionally feature-gated and disabled by default. It
provides:

- a separate WebTransport listener;
- an automatically generated short-lived P-256 certificate and a self-contained
  `/webtransport/certhash/.../p2p/...` multiaddress;
- native `saorsa-transport::TransportAddr` and `saorsa-core::MultiAddr`
  parsing, formatting, validation, and serialization for that address;
- exact path and Origin checks;
- bounded length-prefixed JSON headers on one bidirectional stream per RPC,
  followed by optional raw chunk bytes in either direction;
- `HELLO`, local `FIND_NODE`, local `GET_CHUNK`, `QUOTE_CHUNK`, and paid
  `PUT_CHUNK`;
- a browser application that extracts and pins the certificate from the
  multiaddress, performs the lookup loop,
  downloads public file records, reconstructs complete files, self-encrypts
  uploads, verifies signed storage quotes and commitments, signs EVM payments
  locally, uploads encrypted records, and verifies both chunk and whole-file
  BLAKE3 hashes.

The PoC endpoint descriptors are not yet ML-DSA-signed or disseminated through
the DHT. Peers lacking a browser descriptor remain visible but cannot be
queried by the browser. The PoC must not be enabled on production nodes and is
not evidence that partial fleet deployment is sufficient.

### Local testnet implementation slice

The in-process `ant-devnet` launcher can enable a listener on every node. The
listeners share an in-memory endpoint catalog, allowing each local `FIND_NODE`
answer to attach the self-contained WebTransport multiaddress of every
browser-enabled peer in its routing view. This catalog is explicitly a local
replacement for the future signed DHT endpoint record, not a production
discovery mechanism.

At startup the launcher uses `self_encryption 0.36` to produce encrypted file
chunks and the same public MessagePack `DataMap` used by `ant-client`. It
publishes every record through each candidate node's ordinary PUT handler. It
pre-populates the devnet payment cache for those addresses, while
content-address verification, DHT responsibility, payment-cache admission,
LMDB storage, and verified reads remain active. A read-only HTTP bootstrap
manifest exposes bootstrap multiaddresses, public-file metadata, public EVM
RPC and contract addresses, and the resolved public root DataMap needed by
this local client; it never performs lookup or carries file bytes. Wallet
secrets are never included in the manifest.

The companion JavaScript client and test site live in the `web/` package of the
`ant-client-web-support` repository. It fetches the public DataMap and every
encrypted data chunk directly, applies the native BLAKE3 KDF,
ChaCha20-Poly1305 authentication, and Brotli compression/decompression. It can
verify and save reconstructed files, or obtain quotes, make one batched vault
payment, upload the generated records to closest nodes, and immediately
download the newly published file.

## Consequences

### Positive

- Browsers can become application-level full immutable-data clients without a
  lookup, payment, upload, or download gateway.
- Operators do not manage DNS names or CA certificate issuance.
- Community clients configure one self-contained bootstrap multiaddress per
  seed instead of separate URLs and certificate hashes.
- Rust producers and consumers share the network's native `MultiAddr` codec;
  browser JavaScript implements the same canonical wire syntax.
- Existing PQ node networking and compatibility remain isolated.
- Reliable WebTransport streams match large immutable chunk downloads and
  uploads.
- Endpoint records explicitly bind browser TLS to the node's PQ identity.
- The same transport can run end-to-end through a generic UDP relay.

### Negative / Trade-offs

- Browser-capable nodes run a second UDP listener and a second QUIC/TLS stack.
- Short-lived pinned certificates require automatic overlap, rotation, and
  endpoint-record propagation.
- Current browser TLS is not post-quantum.
- Full direct operation requires broad browser-endpoint coverage among storage
  nodes.
- Relayed nodes consume relay bandwidth even though relays cannot read the
  traffic.
- WebTransport and its HTTP/3 mapping are still evolving and require an
  explicit browser compatibility matrix.
- The PoC's latest WebTransport dependency has a higher feature-specific Rust
  toolchain requirement than the default node build.

### Neutral / Operational

- The official web application still needs to be served from a secure HTTPS
  context; that certificate is unrelated to node operator certificates.
- Origin is policy input, not client authentication. Public deployments still
  need per-IP/session request and byte quotas.
- Bootstrap peers remain necessary, as they are for native clients, but do not
  perform lookup or proxy uploads/downloads.

## Validation

The decision advances beyond PoC only after all of the following are covered:

- Automated protocol framing, oversize-request, malformed-input, path, and
  Origin tests.
- Browser end-to-end tests on current Chrome, Firefox, and Safari from a real
  secure context using both pinned and WebPKI certificates.
- Browser-side iterative lookup parity tests for XOR ordering, `K`, `ALPHA`,
  convergence, retries, and unavailable endpoints.
- Successful streamed downloads at 0 bytes, typical sizes, and 4 MiB, with
  BLAKE3 verification and cancellation/backpressure measurements.
- Paid-upload tests covering quote/commitment tampering, wrong peers, wrong
  content, missing/failed payments, replay/idempotence, wallet rejection, and
  successful native-client retrieval of browser-created files.
- Certificate current/next rotation, stale-record, replay, wrong-peer,
  wrong-network, and hash-mismatch tests.
- Connection floods, stream floods, slow readers, request amplification, and
  global/per-client byte quota tests.
- A fleet test demonstrating that browser endpoint coverage reaches the
  storage nodes selected by native closest-group rules.
- End-to-end relayed WebTransport tests where TLS terminates at the NATed node,
  not the relay.
- Regression tests proving the existing native PQ port and native client
  behavior are unchanged when browser support is disabled.
- Review triggers when the W3C/IETF WebTransport protocol mapping, browser
  support, node storage placement, or Saorsa relay API changes materially.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human
review**. Accepted ADRs are immutable: create a new superseding ADR rather than
editing an Accepted ADR.
