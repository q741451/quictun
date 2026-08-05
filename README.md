# QUICHE

QUICHE stands for QUIC, Http, Etc. It is Google's production-ready
implementation of QUIC, HTTP/2, HTTP/3, and related protocols and tools. It
powers Google's servers, Chromium, Envoy, and other projects. It is actively
developed and maintained.

There are two public QUICHE repositories. Either one may be used by embedders,
as they are automatically kept in sync:

*   https://quiche.googlesource.com/quiche
*   https://github.com/google/quiche

To embed QUICHE in your project, platform APIs need to be implemented and build
files need to be created. Note that it is on the QUICHE team's roadmap to
include default implementation for all platform APIs and to open-source build
files. In the meanwhile, take a look at open source embedders like Chromium and
Envoy to get started:

*   [Platform implementations in Chromium](https://source.chromium.org/chromium/chromium/src/+/main:net/third_party/quiche/overrides/quiche_platform_impl/)
*   [Build file in Chromium](https://source.chromium.org/chromium/chromium/src/+/main:net/third_party/quiche/BUILD.gn)
*   [Platform implementations in Envoy](https://github.com/envoyproxy/envoy/tree/master/source/common/quic/platform)
*   [Build file in Envoy](https://github.com/envoyproxy/envoy/blob/main/bazel/external/quiche.BUILD)

To contribute to QUICHE, follow instructions at
[CONTRIBUTING.md](CONTRIBUTING.md).

QUICHE is only supported on little-endian platforms.

## quictun: TCP-over-QUIC tunnel

This `quictun` branch/fork adds `quictun_server` and `quictun_client`: a pair
of binaries that tunnel raw TCP connections over raw QUIC (transport only --
no HTTP/3, no MASQUE). Each TCP connection gets its own dedicated QUIC
connection and its own dedicated UDP socket -- no connection multiplexing.

```
./quictun_server --listen=[::]:4433 --target=127.0.0.1:12948 --key='a real shared secret'
./quictun_client --local=[::]:12948 --remote=<server-ip>:4433 --key='a real shared secret'
```

`quictun_server` listens for QUIC connections on `--listen` and, for each
one, opens a TCP connection to `--target` and pumps bytes bidirectionally.
`quictun_client` listens for TCP connections on `--local` and, for each one,
opens a new QUIC connection to `--remote` and pumps bytes bidirectionally.
Both `--listen`/`--local` accept IPv6 wildcard addresses (`[::]`) and also
accept IPv4 traffic on the same socket (dual-stack).

The server auto-generates a self-signed TLS certificate in memory on every
start (no files on disk); the client never validates it. The real
authentication is `--key` (required, must match on both ends), checked as an
application-layer preamble at the start of every tunnel.

Flags common to both binaries:

*   `--key` (required): shared secret; the two endpoints must match.
*   `--zero_rtt` (default `true`): attempt 0-RTT resumption for QUIC
    connections made after the first, within one client process's lifetime.
    This tool doesn't defend against 0-RTT replay -- only rely on it on
    trusted/low-risk paths.
*   `--congestion_control` (default `cubic`): `cubic`, `bbr`, `bbr2`, or
    `bbr3`, applied independently to that endpoint's own send direction.
*   `--so_txtime` (default `false`): use SO_TXTIME (Linux packet pacing
    offload) on the UDP send path; falls back silently if unsupported.
*   `--idle_timeout_seconds` (default `60`) and
    `--initial_stream_flow_control_window_kb` (default `512`): tuning knobs
    for idle connections and per-tunnel throughput on high-bandwidth-delay-
    product paths.

`quictun_server`-only: `--listen` (default `[::]:4433`), `--target`
(required). `quictun_client`-only: `--local` (default `[::]:12948`),
`--remote` (required). Run either binary with `--helpfull` for the full flag
list.

This fork's CI builds and releases only `quictun_client`/`quictun_server` by
default. The rest of this section documents QUICHE's own upstream example
tools, which remain in the tree and buildable on demand (e.g.
`bazel build //quiche:quic_client`) but are not part of this fork's default
build/release output.

## Build and run standalone QUICHE

QUICHE has binaries that can run on Linux platforms.

Follow the [instructions](https://bazel.build/install) to install Bazel.

```
sudo apt install libicu-dev clang lld
cd <directory that will be the root of your quiche implmentation>
git clone https://github.com/google/quiche.git
cd quiche
CC=clang bazel build -c opt //...
./bazel-bin/quiche/<target_name> <arguments>
```

There are several targets that can be built and then run. Full usage
instructions are available using the `--helpfull` flag on any binary.

*   quic_packet_printer: from a provided packet, parses and prints out the
    contents that are accessible without decryption.

Usage: `quic_packet_printer server|client <hex dump of packet>`

*   crypto_message_printer: dumps the contents of a QUIC crypto handshake
    message in a human readable format.

Usage: `crypto_message_printer_bin <hex of message>`

*   quic_client: connects to a host using QUIC and HTTP/3, sends a request to
    the provided URL, and displays the response.

Usage: `quic_client <URL>`

*   quic_server: listens forever on --port (default 6121) until halted via
    ctrl-c.

*   masque_client: tunnels to a URL via an identified proxy (See RFC 9298).

Usage: `masque_client [options] <proxy-url> <urls>`

*   masque_server: a MASQUE tunnel proxy that defaults to port 9661.

Usage: `masque_server`

*   web_transport_test_server: a server that clients can connect to via
    WebTransport.

*   moqt_relay: a relay for the Media Over QUIC transport for publishers and
    subscribers can connect to.

Usage: `moqt_relay`
