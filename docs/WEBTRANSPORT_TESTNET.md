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

## Start the browser client

In `ant-client-web-support/web`:

```bash
npm ci
npm run dev
```

Open `http://127.0.0.1:5173`. The app automatically loads the browser manifest.
Use **Download and save file** to fetch the public DataMap and every encrypted
file chunk directly, reconstruct the complete file, validate its whole-file
BLAKE3 hash, and save it under its original filename.

## Automated verification

```bash
cargo test --features webtransport-poc --test webtransport_devnet -- --ignored
```

This starts the five-node network, self-encrypts and publishes a public file
through normal PUT admission with devnet-prepaid cache entries, extracts a
generated certificate pin from the advertised multiaddress, retrieves the
DataMap and encrypted chunks from direct endpoints, and reconstructs the exact
original bytes.

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
