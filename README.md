# quictun

[![Build & Release](https://github.com/q741451/quictun/actions/workflows/build.yml/badge.svg)](https://github.com/q741451/quictun/actions/workflows/build.yml)

A TCP tunnel over QUIC, in the spirit of [kcptun](https://github.com/xtaci/kcptun) —
same idea (forward a local TCP port to a remote target through an obfuscated,
multiplexed tunnel), but QUIC stands in for KCP+smux. It's built as a small
embedder on top of [google/quiche](https://github.com/google/quiche), Google's
production QUIC/HTTP3 implementation.

```
your app --TCP--> quictun-client --QUIC--> quictun-server --TCP--> real target
```

## Why QUIC instead of KCP

kcptun builds reliability, multiplexing, and (optionally) encryption on top of
plain UDP itself (KCP for ARQ, smux for stream multiplexing, a block cipher for
encryption). QUIC already gives you all three natively — congestion-controlled
reliable delivery, TLS 1.3 encryption, and multiplexed streams over one
connection — so quictun doesn't need to reinvent any of that. It uses
WebTransport-over-HTTP/3 as the session/stream abstraction: one persistent QUIC
session per `--conn`, and every proxied TCP connection becomes one WebTransport
stream on it — the direct analogue of kcptun's smux stream.

## Features

- One TCP connection in → one QUIC stream out, and back to TCP on the other
  end. No half-open TCP support (matches kcptun's own `streamCopy` semantics:
  either direction hitting EOF closes both sides).
- Pre-shared key authentication (`--key`) via a header on the WebTransport
  handshake — keeps random UDP scanners from opening tunnels through an
  exposed server. Trust comes from the key, not from certificate validation;
  see [Security model](#security-model).
- Self-signed TLS certificate auto-generated on first run — no PKI setup
  needed, same zero-config feel as kcptun.
- Statically linked binaries — copy one file to a box and run it, no shared
  library version-matching required.
- Tuned to Chrome's actual QUIC defaults (flow-control windows, BBRv2) rather
  than quiche's bare/conservative library defaults.

## Quick start

Grab a prebuilt static binary from [Releases](https://github.com/q741451/quictun/releases)
(currently: `linux-x86_64`, `linux-arm64`), or [build from source](#building-from-source).

**On the remote box** (has the service you want to reach, e.g. something
listening on `127.0.0.1:12948`):

```sh
./quictun-server --listen=0.0.0.0:4433 --target=127.0.0.1:12948 --key='a real shared secret'
```

**On the client box:**

```sh
./quictun-client --local=127.0.0.1:12948 --remote=<remote-ip>:4433 --key='a real shared secret'
```

Anything connecting to `127.0.0.1:12948` on the client now gets tunneled
through QUIC to the target on the remote box.

## Usage

### quictun-client

| Flag | Default | Description |
|---|---|---|
| `--local` | `127.0.0.1:12948` | Local TCP listen address. |
| `--remote` | *(required)* | `quictun-server` address (`host:port`). |
| `--key` | `it's a secret` | Pre-shared key. Overridden by the `QUICTUN_KEY` env var if set. |
| `--conn` | `1` | Number of parallel QUIC sessions to the server (round-robin), like kcptun's `-conn`. |
| `--quiet` | `false` | Suppress per-stream open/close log lines. |

### quictun-server

| Flag | Default | Description |
|---|---|---|
| `--listen` | `0.0.0.0:4433` | QUIC/UDP listen address. |
| `--target` | `127.0.0.1:12948` | TCP address every proxied stream is forwarded to. |
| `--key` | `it's a secret` | Pre-shared key. Overridden by the `QUICTUN_KEY` env var if set. |
| `--cert` | `quictun_cert.pem` | TLS certificate path; self-signed cert auto-generated here if missing. |
| `--certkey` | `quictun_key.pem` | Private key path matching `--cert`; auto-generated alongside it. |
| `--quiet` | `false` | Suppress per-stream open/close log lines. |

Both binaries print INFO-level status (connection established, stream
opened/closed) to stderr by default; pass `--quiet` to suppress the
per-stream lines, or `--stderrthreshold=1` to drop down to warnings only.

## Security model

QUIC/TLS 1.3 already encrypts and authenticates everything on the wire. The
`--key` isn't a cipher key the way kcptun's is — it's used to derive an
HMAC-SHA256 token sent as a header on the WebTransport handshake, which the
server checks before accepting a session. The server's TLS certificate is
self-signed and auto-generated; the client does **not** validate it against a
CA. This is deliberate: identity/trust for this tunnel comes from possession
of the shared key, not from PKI, the same trust model kcptun itself uses.
Anyone who doesn't have `--key` can't open a tunnel, but this is not a
substitute for keeping the key itself secret.

## Building from source

Requires [Bazel](https://bazel.build/install) (or `bazelisk`) and clang-18
(quiche's vendored Chromium `base/` code needs a newer compiler than most
distros ship by default — see the CI workflow for the exact setup).

```sh
CC=clang-18 bazel build -c opt \
  --linkopt=-static --linkopt=-s --linkopt=-Wl,--gc-sections \
  --@com_google_googleurl//build_config:system_icu=0 \
  //quiche/quictun:quictun_client //quiche/quictun:quictun_server
```

Binaries land in `bazel-bin/quiche/quictun/`. See
[`.github/workflows/build.yml`](.github/workflows/build.yml) for the complete,
tested build recipe (toolchain install, caching, multi-arch).

## Supported platforms

| Platform | Status |
|---|---|
| linux/x86_64 | Built and tested on every push |
| linux/arm64 | Built at release time (QEMU) |
| linux/armv7 | Not yet — Bazel ships no 32-bit ARM binary, needs a real cross-toolchain |

## Acknowledgments

- [kcptun](https://github.com/xtaci/kcptun) / [kcp-go](https://github.com/xtaci/kcp-go) — the tunnel design this follows.
- [google/quiche](https://github.com/google/quiche) — the QUIC/HTTP3/WebTransport implementation this is built on. See [`quiche/README.md`](quiche/README.md) for the upstream project.

## License

BSD-style license inherited from google/quiche — see [LICENSE](LICENSE).
