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
quictun_server  (built 2026/08/06 20:14:23)
------------------------------------------------------------------
  listen                                 = [::]:4433
  target                                 = 127.0.0.1:12948
  max_new_connections_per_event_loop     = 100
  max_concurrent_connections             = 5000
  key                                    = <redacted, 20 bytes>
  zero_rtt                               = true
  congestion_control                     = bbr2
  so_txtime                              = false
  transparent                            = false
  idle_timeout_seconds                   = 60
  initial_stream_flow_control_window_kb  = 512
  initial_session_flow_control_window_kb = 512
  udp_socket_buffer_kb                   = 1024
  max_streams_per_connection             = 100
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
| `--transparent` | `false` | Transparent-proxy mode (Linux only). `quictun_client` captures each accepted TCP connection's original destination via `SO_ORIGINAL_DST` (populated by an external iptables/nftables `REDIRECT` rule the operator sets up separately -- quictun itself never touches netfilter config) instead of always tunneling to one fixed address; `quictun_server` connects out to that per-stream destination instead of `--target`. Mutually exclusive with `--target` on the server -- setting both is a startup error, since the two modes speak incompatible wire formats (`--target`'s existing mode has zero framing after the `--key` preamble; transparent mode prepends an address header, IPv4/IPv6 only, no domain names). Both `quictun_client` and `quictun_server` must be started with the same value, the same as `--key`. |
| `--idle_timeout_seconds` | `60` | QUIC connection idle timeout, in seconds. |
| `--initial_stream_flow_control_window_kb` | `512` | Initial per-stream flow-control window advertised to the peer, in KiB. Independent of `--initial_session_flow_control_window_kb` -- since each connection carries exactly one stream, the smaller of the two is what actually caps throughput in practice, so raise both together for high-bandwidth-delay-product paths. |
| `--initial_session_flow_control_window_kb` | `512` | Initial per-session flow-control window advertised to the peer, in KiB. See `--initial_stream_flow_control_window_kb` above. |
| `--udp_socket_buffer_kb` | `1024` | `SO_RCVBUF`/`SO_SNDBUF` size set on every UDP socket quictun creates (one per QUIC connection), in KiB; applies to both the receive and send buffer. Too small a value under load can cause the kernel to drop packets before quictun ever sees them, which looks like network loss to the congestion controller rather than a local buffering problem -- if `/proc/net/snmp`'s `Udp: RcvbufErrors` column (or `nstat -az UdpRcvbufErrors`) climbs during a transfer, raise this. |
| `--startup_bandwidth_kbps` | `0` | If > 0, bootstrap every new connection's congestion controller with this assumed starting bandwidth (Kbps, i.e. kilobits/sec -- *not* KB/s or bytes) instead of ramping up from scratch. Only affects the controller while still in its startup/slow-start phase; has no effect once a connection reaches steady state. `0` disables this (normal cold-start ramp-up). Pairs with `--startup_rtt_ms`; set both sides (client and server) to the same values, since each governs only that endpoint's own send direction. |
| `--startup_rtt_ms` | `0` | Assumed starting RTT in milliseconds, paired with `--startup_bandwidth_kbps` -- only used, and only meaningful, if that flag is also `> 0`. `0` falls back to QUICHE's own initial RTT guess (100ms). |
| `--max_streams_per_connection` | `100` | Max concurrent bidirectional streams this endpoint will accept as incoming from its peer at once. quictun's streams are always client-initiated, so in practice only the *server's* value does anything -- the client's own copy is accepted for symmetry but has nothing to bite, since the server never opens a stream to the client. Matters for `--quic_conn` pooling: with `N` pool slots round-robining accepted TCP connections, one pooled connection's concurrently-open stream count is the pool's live TCP count divided across those `N` slots, not `N` itself -- a *small* `--quic_conn` concentrates more load onto fewer connections, making this cap more likely to matter than a large one does. The default (`100`) is QUICHE's own real default -- quictun applies no override unless you change this. Not a hard lifetime cap: it's a sliding window that grows back by one every time an existing stream closes, so it only blocks new streams while this many are open *at once*, not after this many have ever been opened in total. A peer that opens a stream beyond what's currently granted anyway is a protocol violation -- not a per-stream rejection but the *whole connection* closing, taking every other stream sharing it down too. |

### `quictun_server`-only

| Flag | Default | Description |
| --- | --- | --- |
| `--listen` | `[::]:4433` | Address:port to accept incoming QUIC (UDP) connections on. |
| `--target` | *(required unless `--transparent`)* | Address:port of the TCP server to connect to for each accepted tunnel. Must be left unset when `--transparent` is enabled -- see that flag above. |
| `--max_new_connections_per_event_loop` | `100` | Caps how many brand-new connections `quictun_server` will create per event-loop iteration (~every 50ms); a packet that would create another past that budget is dropped once it hits zero for that tick. Not a permanent rejection -- a legitimate client's own QUIC handshake retransmission logic retries on its own, so this only spreads a burst of genuine connection attempts across a couple of ticks. Exists to bound how much CPU/memory a flood of spoofed-source garbage packets can force the server to spend in one tick. The default (`100`) matches real QUICHE's own `QuicBufferedPacketStore::kDefaultMaxConnectionsInStore`. |
| `--max_concurrent_connections` | `5000` | Hard cap on how many connections (established or still mid-handshake) `quictun_server` will have open at once; a packet that would create another past that cap is dropped. Each connection holds at least one dedicated UDP socket, so this bounds fd/memory exhaustion from a flood of forged connection attempts rather than relying on the OS fd limit to be the thing that eventually says no. The default (`5000`) is meant to be generous relative to any realistic legitimate load. |

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
binaries for `x86_64`, `x86`, `arm64`, `armv7`, `mipsel`, and `riscv64` via
[`.github/workflows/build.yml`](.github/workflows/build.yml), using a
pinned, from-scratch toolchain (Chromium's pinned clang, plus a musl libc,
a compiler-rt, and a libc++/libc++abi/libunwind all built from source by
that same clang) so builds don't depend on the Ubuntu version running the
build -- or on its libc at all. Grab them from the *Artifacts* section of the
corresponding run under the [Actions tab](../../actions) -- there is no
separate GitHub Releases page.

## Building from source

```
sudo apt install cmake ninja-build
git clone -b quictun https://github.com/q741451/quictun.git
cd quictun
bash build/toolchain/setup_toolchain.sh x64
./build/regen_quictun_build_timestamp.sh
bazel build -c opt --platforms=//build/toolchain:linux_x64 //quiche:quictun_client //quiche:quictun_server
./bazel-bin/quiche/quictun_client --helpfull
```

No compiler is installed from the distro, and none is used: `cmake`,
`ninja`, `curl`, `make` and `tar` are the only host tools involved, and
they are only there to *drive* the build of the pinned toolchain.

`bash build/toolchain/setup_toolchain.sh x64` downloads Chromium's pinned
clang and builds musl, compiler-rt and libc++ against it, under
`build/toolchain/out/` -- a working directory inside the repo, so it needs
no root and touches nothing outside the checkout. It also writes
`build/toolchain/toolchain_paths.bzl`, which `build/toolchain/BUILD.bazel`
loads, so this step is **required**: it is gitignored rather than checked
in, and skipping it fails the build at analysis time with a missing-file
error on that `load()`. Rerunning it is cheap -- each piece is skipped if
already built.

`./build/regen_quictun_build_timestamp.sh` writes the current time into a
small generated header the [startup banner](#startup-banner) reads --
required for the same reason (gitignored, not checked in), and worth
rerunning before each later rebuild too, or the banner will just keep
showing this first build's time.

`--platforms=//build/toolchain:linux_x64` selects this repo's pinned
toolchain (see `build/toolchain/BUILD.bazel`); other supported values are
`linux_x86`, `linux_arm64`, `linux_armv7`, `linux_mipsel` and
`linux_riscv64`. Cross-compiling to any of them means running
`setup_toolchain.sh` for that architecture too (and for `x64` as well,
which is what Bazel builds host-side tools like protoc with).

No `--linkopt` is needed for a fully static binary: musl is configured
with `--disable-shared`, so `-static-pie` is part of the toolchain itself
(`build/toolchain/toolchain_flags.bzl`) on every architecture rather than
something the command line adds.

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
