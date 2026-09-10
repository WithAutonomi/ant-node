# Browser-enabled local testnet

This workflow starts a five-node local Autonomi network where every node has a
direct WebRTC Direct endpoint. Startup publishes a default immutable test file
and serves browser bootstrap metadata; the companion site lives in the sibling
`ant-client-browser-sdk` repository, with Rust/WASM from `ant-client-web-support`.

## Start the node testnet

Rust 1.91 or newer is the shared native/WASM baseline.
The startup and transport policy is recorded in [ADR-0013](adr/ADR-0013-direct-browser-clients-over-webrtc-direct.md).

```bash
cargo run --bin ant-devnet --features test-utils -- \
  --preset minimal \
  --base-port 23000 \
  --webrtc-direct \
  --webrtc-direct-base-port 24000 \
  --serve-port 25000 \
  --enable-evm \
  --enable-logging
```

`test-utils` explicitly enables development-only prepaid file seeding. Without
it, the listeners and ordinary paid uploads still work, but manifests contain
`files: []`; an explicit `--public-file` is rejected before startup. Production
builds do not expose the prepaid cache insertion API.

The services are:

| Purpose | Address |
|---|---|
| Native node QUIC | UDP 127.0.0.1:23000-23004 |
| Direct browser WebRTC Direct | UDP 127.0.0.1:24000-24004 |
| Native devnet manifest | http://127.0.0.1:25000/api/devnet-manifest.json |
| Browser bootstrap manifest | http://127.0.0.1:25000/api/browser-manifest.json |
| Manifest service metadata | http://127.0.0.1:25000/api/info |
| Local Anvil JSON-RPC | printed at startup (random loopback port) |

When `--serve-port` is omitted with `--webrtc-direct`, port 25000 is used. Pass
`--public-file /path/to/file` to replace the built-in
`autonomi-browser-testnet.txt`. The generated default is 5 MiB so the demo
necessarily reconstructs multiple storage records. A custom file may be up to
1 GB (1,000,000,000 bytes) in this local in-memory launcher. The practical
limit depends on the browser having enough available memory.

The browser manifest contains every node's self-contained WebRTC Direct
multiaddress, with its certificate SHA-256 multihash and peer ID embedded,
plus the public DataMap address, plaintext file hash, and resolved
reconstruction metadata. The HTTP server provides bootstrap metadata only;
the DataMap and file bytes are read from storage nodes over WebRTC Direct.
Each address string is serialized directly from `saorsa_core::MultiAddr`; the
node does not maintain a browser-specific multiaddress codec.

`--webrtc-direct` requires an explicit payment network. For this local test,
`--enable-evm` starts Anvil and startup prints a **Funded wallet private key**. This
is a disposable local Anvil key for browser upload testing. HELLO and the browser
manifest contain only `chain_id`, `payment_token_address`, and
`payment_vault_address`. Local Anvil uses chain ID 31337. Neither the verification
RPC URL nor the funded key is included in browser metadata.

Browser protocol v5 and browser manifest v6 require matching node, Rust/WASM
client, and SDK versions. The application or wallet owns its payment provider;
no browser RPC setting is needed on the node. For a custom EVM network, the node
privately resolves `eth_chainId` from its verification RPC when starting the
browser listener. Failure to resolve the chain ID fails listener startup.
Built-in Arbitrum networks use their known chain IDs. Clients compare payment
chain and contract identities, so they can use a different provider for the same
network.

## Start the browser client

In `ant-client-browser-sdk`:

```bash
npm ci
ANT_CLIENT_DIR=../ant-client-web-support npm run sync:wasm
npm run dev
```

Open the URL printed by Vite. Paste a node's WebRTC Direct multiaddress from
the browser manifest and click **Connect**. To upload, choose a file, paste the
Anvil JSON-RPC URL and funded private key printed by ant-devnet, and use
**Pay and upload**. The page self-encrypts locally, verifies node
quotes, signs the approval/payment locally, and sends only encrypted records
and public payment proof to nodes. The
result address is placed into the download field automatically.

Use **Download and save** to fetch the public DataMap and every encrypted
file chunk directly, reconstruct the complete file, validate its whole-file
BLAKE3 hash, and save it under its original filename.

For a browser-supported video, use **Stream as media** and then the native
video controls. The Rust/WASM reader fetches and decrypts only records
overlapping the media element's requested byte ranges. A same-origin service
worker provides standard HTTP range responses locally; no file bytes pass
through the manifest server or another gateway.

## Automated verification

```bash
cargo test --locked --test webrtc_direct_devnet --features test-utils -- --include-ignored
```

This starts Anvil and the five-node network, self-encrypts and publishes a
default public file through normal PUT admission with devnet-prepaid cache
entries, extracts a generated certificate pin from the advertised
multiaddress, retrieves and reconstructs it, then obtains a real signed quote,
pays it on-chain, uploads a fresh record through paid `PUT_CHUNK`, and reads it
back through WebRTC Direct.

The same suite checks that encrypted HELLO and browser manifests omit a custom
verification URL containing dummy credentials and API keys, and that invalid
chain-ID responses fail without exposing provider details.

## LAN testing

Use `--host <LAN_IPV4>` to advertise the literal LAN address:

```bash
cargo run --bin ant-devnet --features test-utils -- \
  --preset minimal \
  --host 192.168.1.50 \
  --webrtc-direct \
  --serve-port 25000 \
  --enable-evm \
  --enable-logging
```

Expose the client dev server on the LAN with `npm run dev -- --host 0.0.0.0`
and obtain a bootstrap address from
`http://192.168.1.50:25000/api/browser-manifest.json`. Both the native and
WebRTC Direct UDP ranges must be reachable. Do not use this unsigned local
manifest mode on a public network.

## Public Internet smoke testing

The standard `ant-node` build includes and enables WebRTC Direct. An enabled
listener's configuration, payment-network, certificate, or bind failure aborts
node startup. Use `--disable-webrtc-direct` (or
`ANT_DISABLE_WEBRTC_DIRECT=true`) to disable it explicitly.

Like native QUIC, port `0` asks the OS to choose an available UDP port; an
explicit `--webrtc-direct-port` remains fixed. Wildcard listeners advertise a
same-family non-relay IP from the canonical native address view. They wait for
usable native address discovery, refresh the published endpoint as it changes,
and never fabricate a route-probe or loopback fallback. The endpoint file is
created only once an address is known.

Configure an explicit WebRTC port and permit inbound UDP on that port when a
stable bootstrap endpoint or firewall rule is needed. Retain the node identity
and certificate and use a fixed public IP. Certificate persistence alone does
not keep an OS-assigned port stable. An explicit
`--webrtc-direct-advertised-addr` can override the public IP and external port
without a bind override. The development launcher above uses explicit port
ranges separately for its in-process nodes.

Deploy the normal testnet against this checkout, for example:

```bash
cd ../ant-testnet
python3.11 testnet.py \
  --saorsa-node-repo ../ant-node-web-support \
  deploy
```

`ant-testnet` always keeps bootstrap droplets public. Read node 0's canonical
address using its existing shell command, without modifying the deployment
tool:

```bash
python3.11 testnet.py shell --droplet 0
cat /var/lib/ant/node-0/webrtc-direct.multiaddr
exit
```

Start `ant-client-browser-sdk`, paste that address into the demo, and use
**Connect**. The operation installs the single address as
the Rust browser client's seed without DNS or a browser manifest. The address
contains only the public DTLS certificate hash and ANT peer ID; it contains no
secret key material. To disable the listener in a custom node configuration,
set `webrtc_direct.enabled = false` or use `--disable-webrtc-direct`. A build
with `--no-default-features` omits the listener stack; it still uses the same
pinned native core and protocol dependencies. This is not a dependency rollback.

Public listeners apply an independent resource envelope; the native QUIC
limits are not shared with browser traffic. The defaults are:

| Setting | Default | Scope |
|---|---:|---|
| `max_connections` | 32 | listener |
| `max_connections_per_ip` | 4 | IPv4 address or IPv6 /64 |
| `max_channels_per_connection` | 2 | association |
| `max_channels` | 32 | listener and channel-handler tasks |
| `max_concurrent_requests` | 16 | listener work slots |
| `max_requests_per_second` | 256 | listener work token bucket |
| `max_requests_per_second_per_ip` | 32 | source-prefix work token bucket |
| `max_requests_per_second_per_connection` | 16 | association work token bucket |
| `max_in_flight_bytes` | 64 MiB | listener frame memory |
| `max_in_flight_bytes_per_ip` | 16 MiB | source-prefix frame memory |
| `max_request_bytes` | 64 KiB | JSON request header |

The per-IP ceilings must remain strictly below their corresponding global
ceilings. The product of the per-IP connection and per-connection channel
limits must also remain below both global channel and request concurrency.
Invalid combinations fail node startup instead of silently removing the
headroom reserved for other clients. Native IPv6 sources share a /64 quota,
and IPv4-mapped IPv6 shares its IPv4 quota. The transport's pre-association
admission and application budgets use the same source-key function. Rate buckets permit a one-second burst; overload closes the
offending channel or association without queueing more handler tasks. PQ
handshakes consume the same work slots and rate tokens as RPCs, and response
writes use size-scaled deadlines so slow readers release their reservations.

Each node publishes its certificate-pinned WebRTC Direct multiaddress through
Saorsa's extensible V2 address plane as transport `WebRtcDirect`, independently
of its reachability class. Native peers send both signed V2 records and the
unchanged V1 QUIC projection; native publication does not negotiate a version
through identity capabilities. Older peers process V1 and ignore the separate
V2 topic. `FindNodeV2` forwards original owner-signed records. The browser
verifies these proofs before dialing and verifies the peer-ID and certificate
binding during the PQ session and HELLO. V2 uses nonempty replacements with
no withdrawal operation or routine expiry. The browser RPC `addr-v2` capability
requests these records and is independent of native publication.
Consequently one pasted address is enough to enter the network and discover
the browser endpoints of closest peers across independently deployed
processes. Native QUIC dialing ignores the supplemental transport entry.

The 2026-08-27 public smoke run used the former protocol v3 and headless
Chromium only. From one bootstrap address it traversed multiple independent
nodes, obtained four storage quotes from non-bootstrap closest nodes,
submitted one payment, and stored all four encrypted records. It is historical
connectivity evidence, not v5 or cross-browser acceptance evidence. Nodes
behind the testnet's deliberate inbound-NAT rules remain unreachable without
relayed WebRTC, so their 10-second DataChannel timeouts currently make this
smoke path slower than an all-public fleet.
