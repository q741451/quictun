# quictun: TCP-over-raw-QUIC tunnel

`quictun` tunnels raw TCP connections over QUIC transport -- no HTTP/3, no
MASQUE, no multiplexing. Every TCP connection gets its own dedicated QUIC
connection and its own dedicated UDP socket. It's two small binaries,
`quictun_server` and `quictun_client`, built on top of Google's
[QUICHE](#quiche) QUIC implementation.

```
quictun_server --listen=[::]:4433 --target=127.0.0.1:12948 --key='a real shared secret'
quictun_client --local=[::]:12948 --remote=<server-ip>:4433 --key='a real shared secret'
```

`quictun_server` listens for QUIC connections on `--listen` and, for each
one, opens a TCP connection to `--target` and pumps bytes bidirectionally.
`quictun_client` listens for TCP connections on `--local` and, for each one,
opens a new QUIC connection to `--remote` and pumps bytes bidirectionally.
Both `--listen`/`--local` accept IPv6 wildcard addresses (`[::]`) and also
accept IPv4 traffic on the same socket (dual-stack).

## Why raw QUIC

Everything here is Google's own production QUIC transport implementation,
minus the HTTP/3 layer QUICHE normally carries on top of it. That buys the
usual QUIC properties -- 1-RTT (or 0-RTT) handshakes, congestion control,
loss recovery, and connection migration -- without paying for a protocol
layer this tool has no use for. One QUIC connection (and one UDP socket) per
TCP connection keeps head-of-line blocking and fairness scoped to a single
tunneled connection instead of shared across all of them.

## Security model

The server auto-generates a self-signed TLS certificate in memory on every
start (no files ever touch disk); the client does not validate it -- TLS
here provides transport encryption, not authentication. The actual
authentication is `--key`: a shared secret checked as an application-layer
preamble at the start of every tunnel, before any TCP data is relayed.
Traffic without a matching key is rejected before it reaches `--target`.

`--zero_rtt` (default `true`) lets repeat connections skip a round trip by
resuming the previous handshake. This tool does **not** defend against
0-RTT replay attacks -- only enable it on trusted or low-risk paths; disable
with `--zero_rtt=false` if that matters for your deployment.

## Startup banner

Both binaries log a banner once at startup: the binary name, the exact
build's compile date/time, and every active configuration value (with
`--key` redacted to just its byte length, so the log is safe to paste into a
bug report). This makes "which build, with what config, is actually
running" answerable from the log alone, with no need to cross-reference a
git hash or re-read a shell history:

```
==================================================================
quictun_server  (built Aug  6 2026 20:14:23)
------------------------------------------------------------------
  listen                                 = [::]:4433
  target                                 = 127.0.0.1:12948
  key                                    = <redacted, 20 bytes>
  zero_rtt                               = true
  congestion_control                     = bbr2
  so_txtime                              = false
  idle_timeout_seconds                   = 60
  initial_stream_flow_control_window_kb  = 512
==================================================================
```

## Configuration reference

Every flag below can also be listed at runtime with `--helpfull`.

### Shared by both binaries

| Flag | Default | Description |
| --- | --- | --- |
| `--key` | *(required)* | Shared secret checked as an application-layer preamble at the start of every tunnel. The two endpoints must be configured with the identical value. |
| `--zero_rtt` | `true` | Attempt 0-RTT resumption for QUIC connections made after the first, within one process's lifetime. See [Security model](#security-model) for the replay caveat. |
| `--congestion_control` | `cubic` | `cubic`, `bbr`, `bbr2`, or `bbr3`. Applies independently to *this endpoint's own send direction* -- client and server each pick their own, and the two need not match. An unrecognized value falls back to `cubic` with a logged warning rather than failing to start. |
| `--so_txtime` | `false` | Use `SO_TXTIME` (Linux packet pacing offload) on the UDP send path. Falls back silently if the kernel doesn't support it. |
| `--idle_timeout_seconds` | `60` | QUIC connection idle timeout, in seconds. |
| `--initial_stream_flow_control_window_kb` | `512` | Initial flow-control window advertised to the peer, in KiB. Since each connection carries exactly one stream, this is effectively the per-tunnel receive buffer budget -- raise it for high-bandwidth-delay-product paths. |

### `quictun_server`-only

| Flag | Default | Description |
| --- | --- | --- |
| `--listen` | `[::]:4433` | Address:port to accept incoming QUIC (UDP) connections on. |
| `--target` | *(required)* | Address:port of the TCP server to connect to for each accepted tunnel. |

### `quictun_client`-only

| Flag | Default | Description |
| --- | --- | --- |
| `--local` | `[::]:12948` | Address:port to accept incoming TCP connections on. |
| `--remote` | *(required)* | Address:port of the `quictun_server` to connect to for each accepted TCP connection. |

All address flags accept `host:port` or `[ipv6-literal]:port`; DNS names are
not supported (IP literals only). `[::]` (IPv6 wildcard) also accepts IPv4
traffic on the same socket.

## Getting binaries

Every push to the `quictun` branch builds static, self-contained Linux
binaries for `x86_64`, `arm64`, `armv7`, and `mipsel` via
[`.github/workflows/build.yml`](.github/workflows/build.yml), using a
pinned, from-scratch, Chromium-style toolchain (pinned clang, a from-source
libc++, and a pinned glibc snapshot) so builds don't depend on the Ubuntu
version running the build. Grab them from the *Artifacts* section of the
corresponding run under the [Actions tab](../../actions) -- there is no
separate GitHub Releases page.

## Building from source

```
sudo apt install libicu-dev clang lld
git clone -b quictun https://github.com/q741451/quictun.git
cd quictun
bazel build -c opt --platforms=//build/toolchain:linux_x64 //quiche:quictun_client //quiche:quictun_server
./bazel-bin/quiche/quictun_client --helpfull
```

`--platforms=//build/toolchain:linux_x64` selects this repo's pinned
toolchain (see `build/toolchain/BUILD.bazel`); other supported values are
`linux_arm64`, `linux_armv7`, and `linux_mipsel`. Add
`--linkopt=-static-pie` (x86_64/arm64) or `--linkopt=-static` (armv7/mipsel)
for the same fully static binaries CI produces.

---

## QUICHE

This fork is built on top of [QUICHE](https://github.com/google/quiche),
Google's production-ready implementation of QUIC, HTTP/2, HTTP/3, and
related protocols and tools. It powers Google's servers, Chromium, Envoy,
and other projects.

QUICHE is only supported on little-endian platforms.

This fork's CI builds and releases only `quictun_client`/`quictun_server` by
default. QUICHE's own upstream example tools (`quic_client`, `quic_server`,
`masque_client`, `masque_server`, etc.) remain in the tree and are buildable
on demand (e.g. `bazel build //quiche:quic_client`), but are not part of
this fork's default build/release output. See
[upstream's own README](https://github.com/google/quiche/blob/main/README.md)
for details on those tools and on embedding QUICHE itself.
