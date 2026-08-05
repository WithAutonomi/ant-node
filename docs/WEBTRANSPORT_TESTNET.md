# Browser-enabled local testnet

This workflow starts a five-node local Autonomi network where every node has a
direct WebTransport endpoint. Startup publishes a default immutable test file
and serves browser bootstrap metadata; the companion site lives in the sibling
`ant-client-web-support` repository.

## Start the node testnet

Rust 1.88 or newer is required by the optional WebTransport dependency.

```bash
cargo run --features webtransport-poc --bin ant-devnet -- \
  --preset minimal \
  --base-port 23000 \
  --webtransport \
  --webtransport-base-port 24000 \
  --serve-port 25000 \
  --enable-evm \
  --enable-logging
```

The services are:

| Purpose | Address |
|---|---|
| Native node QUIC | UDP 127.0.0.1:23000-23004 |
| Direct browser WebTransport | UDP 127.0.0.1:24000-24004 |
| Native devnet manifest | http://127.0.0.1:25000/api/devnet-manifest.json |
| Browser bootstrap manifest | http://127.0.0.1:25000/api/browser-manifest.json |
| Manifest service metadata | http://127.0.0.1:25000/api/info |
| Local Anvil JSON-RPC | printed at startup (random loopback port) |

When `--serve-port` is omitted with `--webtransport`, port 25000 is used. Pass
`--public-file /path/to/file` to replace the built-in
`autonomi-browser-testnet.txt`. The generated default is 5 MiB so the demo
necessarily reconstructs multiple storage records. A custom file may be up to
64 MiB in this local in-memory launcher.

The browser manifest contains every node's self-contained WebTransport
multiaddress, with its certificate SHA-256 multihash and peer ID embedded,
plus the public DataMap address, plaintext file hash, and resolved
reconstruction metadata. The HTTP server provides bootstrap metadata only;
the DataMap and file bytes are read from storage nodes over WebTransport.
Each address string is serialized directly from `saorsa_core::MultiAddr`; the
node does not maintain a browser-specific multiaddress codec.

`--webtransport` requires an explicit payment network. For this local test,
`--enable-evm` starts Anvil and startup prints a **Funded wallet private key**. This
is a disposable local Anvil key for browser upload testing. The browser manifest
contains only public RPC/token/vault configuration and never contains the
key.
If `HELLO.payment.rpc_url` shows `https://arb1.arbitrum.io/rpc`, the devnet was
started without local Anvil; stop it and restart with the command above.

## Start the browser client

In `ant-client-web-support/web`:

```bash
npm ci
npm run dev
```

Open `http://127.0.0.1:5173`. The app automatically loads the browser manifest.
To upload, choose a file, paste the funded private key printed by ant-devnet,
and use **Pay and upload file**. The page self-encrypts locally, verifies node
quotes, signs the approval/payment locally, and sends only encrypted records
and public payment proof to nodes. The key field is cleared immediately. The
result address is placed into the download field automatically.

Use **Download and save file** to fetch the public DataMap and every encrypted
file chunk directly, reconstruct the complete file, validate its whole-file
BLAKE3 hash, and save it under its original filename.

## Automated verification

```bash
cargo test --features webtransport-poc --test webtransport_devnet -- --ignored
```

This starts Anvil and the five-node network, self-encrypts and publishes a
default public file through normal PUT admission with devnet-prepaid cache
entries, extracts a generated certificate pin from the advertised
multiaddress, retrieves and reconstructs it, then obtains a real signed quote,
pays it on-chain, uploads a fresh record through paid `PUT_CHUNK`, and reads it
back through WebTransport.

## LAN testing

Use `--host <LAN_IPV4>` and add the exact site origin:

```bash
cargo run --features webtransport-poc --bin ant-devnet -- \
  --preset minimal \
  --host 192.168.1.50 \
  --webtransport \
  --webtransport-origin http://192.168.1.50:5173 \
  --serve-port 25000 \
  --enable-logging
```

Expose the client dev server on the LAN and change its manifest URL to
`http://192.168.1.50:25000/api/browser-manifest.json`. Both the native and
WebTransport UDP ranges must be reachable. Do not use this unsigned local
manifest mode on a public network.
