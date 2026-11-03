# ADR-0027: Map the browser listener's port through UPnP

- **Status:** Proposed
- **Date:** 2026-11-02
- **Decision owners:** <pending>
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** [ADR-0015](./ADR-0015-direct-browser-clients-over-webrtc-direct.md)
  (amends its "NAT and relays" section),
  [ant-browser-sdk#10](https://github.com/WithAutonomi/ant-browser-sdk/issues/10)
  (browser "Missing chunk" on a file the native client downloads),
  ant-client `ant node add --webrtc-port` (a fixed browser port operators can forward)

## Context

A browser reaches a node only through its WebRTC Direct endpoint (ADR-0015). By
default the listener binds a wildcard address on an OS-chosen port and
advertises the native self-address view's IP with that port. The native QUIC
endpoint asks the local gateway for a UPnP port mapping; the browser listener
does not. Behind a home router the advertised address therefore points at a port
the router drops: a native client still reaches the node, directly or through a
MASQUE relay, but a browser cannot. ADR-0015 records that NATed WebRTC nodes are
unsupported.

On mainnet this decides whether browsers can read data. A census on 2026-11-02
dialled the WebRTC endpoints of 802 nodes from Chromium, one at a time with a
9 s ICE budget, twice each:

| Signed native record | Nodes | Never answered ICE |
|---|---:|---:|
| all | 802 | 411 (51%) |
| QUIC `Unverified` only (no confirmed public address) | 87 | 86 |
| QUIC `Direct` on a port above 20000 | 244 | 228 |
| QUIC `Direct` on a port below 20000 | 471 | 97 |

The outcome was stable for each node and almost always for each IP. Of 61
WebRTC-dead nodes with a `Direct` address, 25 answered a plain QUIC dial on it:
the host is up and its forwarded native port is open, but nothing forwards the
browser port.

Node IDs are hashes, so reachability is independent of a record's address. With
half the endpoints dead, about 0.5^7 ≈ 0.9% of records have no browser-reachable
peer among their seven nearest. ant-browser-sdk#10 is one: both failing chunks
of a 4.6 GB file are held by all nine of their nearest peers, every one of them
WebRTC-dead, and the reporter's native client fetched them through MASQUE
relays. A browser could read them only from two holders further out, and it
reports the chunk missing when those are unavailable.

## Decision Drivers

- Browser reads must not depend on a few holders outside the close group.
- Home operators should not need to know that browsers use a second port.
- No new protocol, wire format or relay service.
- An operator's explicit address and bind choices stay authoritative.
- Fail safe: a gateway without UPnP leaves publication exactly as before.

## Considered Options

1. **Keep publishing the unmapped port.** About half of browser dials keep failing.
2. **Map the browser port through UPnP, as the native endpoint already does.**
   Covers home routers with UPnP enabled, with no operator action.
3. **A fixed default browser port.** Operators must still forward it by hand;
   useful beside option 2, not instead of it. The node already has
   `--webrtc-direct-port`; ant-client exposes it in `ant node add`.
4. **Relayed or signaled WebRTC for NATed nodes.** Reaches nodes behind any NAT
   but needs a signaling and relay design (ADR-0015, "NAT and relays"). Future work.
5. **Withhold endpoints that are not reachable.** Saves browsers a dial timeout
   but needs a reachability probe the node lacks, and makes no node reachable.

## Decision

We will choose option 2.

- A listener that chooses its own public address, one bound to a wildcard
  address with no `advertised_addr`, starts saorsa-transport's
  `UpnpMappingService` for its port with the default configuration. An explicit
  bind address or advertised address is the operator's, and is not mapped.
- The gateway's mapping, when it exists and matches the listener's address
  family, is advertised before the native self-address view. The service asks
  for the listener's own port first, so the advertised port is usually unchanged.
- The mapping is best effort. Without a gateway, or when the gateway refuses,
  reports a non-public external IP (including CGNAT) or loses the lease, the
  endpoint falls back to the native view as before. The existing one-second
  publication refresh picks up each change.
- An endpoint only the mapping reached, because the native view yields no
  address or a different one, is advertised only while the gateway holds the
  mapping. When the mapping ends and the native view yields nothing, the node
  withdraws it from HELLO, the in-process catalog and the DHT address record,
  then removes the endpoint file. Those publications cannot fail, so a file
  error never keeps the endpoint advertised; the node retries the file on each
  refresh until it is gone. An endpoint the native view still yields stays
  published as before.
- Graceful shutdown removes the mapping; otherwise its one-hour lease expires.

There is no new configuration. Setting `--webrtc-direct-advertised-addr` or an
explicit `--webrtc-direct-bind` IP opts a node out.

## Consequences

### Positive

- Nodes on home connections whose router has UPnP enabled become reachable from
  browsers with no operator action.
- Browser reads gain holders inside the close group, so fewer records depend on
  a few distant replicas.

### Negative / Trade-offs

- One more gateway mapping per node, beside the native one. Routers that cap
  mappings may refuse it; the node then behaves as before.
- No help behind CGNAT, double NAT, routers with UPnP disabled, or networks that
  block inbound UDP. Those nodes still need a forwarded fixed port (option 3) or
  a future relay (option 4).
- UPnP lets any LAN process open router ports; this adds no new kind of exposure,
  since the node already maps its native port the same way.

### Neutral / Operational

- No wire, storage, protocol or payment change. Browsers see only a different
  advertised address.
- Local devnets set an advertised address for every node, so tests and devnets
  never contact a gateway.

## Validation

- Unit tests: only a wildcard listener without an advertised address maps its
  port; a mapping is advertised before the native view, needs no native
  discovery, is ignored in the other address family, and an operator's
  advertisement still wins; only an address the native view lacks depends on
  the mapping.
- Refresh-level tests: on a node with no native address, a published mapping
  is withdrawn from HELLO state, the endpoint file, the catalog and the DHT
  supplemental record when the mapping ends. When the endpoint file cannot be
  removed, the endpoint still leaves HELLO, the catalog and the DHT record, and
  the next refresh removes the file once it can.
- Live check behind a consumer gateway (Sagemcom F3896LG, 2026-11-02): a node on
  this change, bootstrapped to a local devnet with default WebRTC settings,
  bound the listener on an OS-chosen port, the gateway granted a UDP mapping
  for that same external port, the node advertised the public IP with it, and
  graceful shutdown removed the mapping. A node on `main` got a mapping for its
  native port only.
- After release, rerun the mainnet census. The share of WebRTC endpoints that
  never answer should fall among nodes with a `Direct` QUIC address on a high port.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human
review**. Accepted ADRs are immutable: create a new superseding ADR rather than
editing an Accepted ADR.
