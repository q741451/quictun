// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Command-line flags shared by quictun_client and quictun_server, plus a
// small "host:port" / "[ipv6]:port" address parser used by both binaries'
// --listen/--target/--local/--remote flags. Binary-specific flags are
// defined directly in quictun_client_bin.cc / quictun_server_bin.cc, since
// nothing outside those files needs to read them.

#ifndef QUICHE_QUIC_TOOLS_QUICTUN_FLAGS_H_
#define QUICHE_QUIC_TOOLS_QUICTUN_FLAGS_H_

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_socket_address.h"

namespace quic {

// The subset of tuning flags shared by both binaries. Read once at startup
// (see GetQuictunTuningOptionsFromFlags()) and passed down as a plain struct
// rather than as raw absl::Flag<T> references, so the rest of quictun's code
// doesn't need to depend on the flag-parsing machinery at all.
struct QuictunTuningOptions {
  // Shared secret checked as an application-layer preamble at the start of
  // every tunnel (see quictun_client_connection.cc /
  // quictun_server_connection.cc). Must match on both ends.
  std::string psk;

  // Whether to attempt 0-RTT resumption for new QUIC connections. See
  // quictun_client_driver.h for where this is actually consumed.
  // Client-only, and set by quictun_client_bin.cc rather than by
  // GetQuictunTuningOptionsFromFlags(): the server issues session tickets
  // unconditionally, so this only decides whether the client attempts
  // resumption. Left at its default in quictun_server, where nothing reads
  // it -- see this field's flag definition for the rest.
  bool zero_rtt = true;

  // "cubic" | "bbr" | "bbr2" | "bbr3". Applies to this endpoint's own send
  // direction only.
  std::string congestion_control = "cubic";

  // Transparent-proxy mode: quictun_client captures each accepted TCP
  // connection's original destination (Linux SO_ORIGINAL_DST, i.e. an
  // external iptables/nftables REDIRECT rule) instead of always tunneling
  // to a single fixed address, and quictun_server connects out to that
  // per-stream destination instead of --target. Mutually exclusive with
  // --target: the existing pure-port-forward wire format has no framing at
  // all (whatever bytes follow the --key preamble are raw TCP payload,
  // forwarded verbatim), so a transparent-mode client/server pair speaks a
  // different, incompatible wire format (an address header right after the
  // --key preamble) rather than trying to auto-negotiate the two -- both
  // ends must be configured with the same value, the same way both ends
  // must be configured with the same --key. false (default) is a
  // no-op -- quictun's original pure-port-forward behavior, unchanged.
  bool transparent = false;

  // Whether to use SO_TXTIME (Linux packet pacing offload) on the UDP send
  // path. Falls back silently if the kernel doesn't support it.
  bool so_txtime = false;

  QuicTime::Delta idle_timeout = QuicTime::Delta::FromSeconds(60);

  // Initial per-stream flow-control window. With --quic_conn=0 (default,
  // one stream per connection) the smaller of this and
  // initial_session_flow_control_window_bytes is, in practice, what caps
  // throughput on high-bandwidth-delay-product paths; with --quic_conn
  // pooling multiple streams onto one connection, the session window also
  // caps their combined total -- raise both together either way.
  // Independently tunable from the session window (unlike stock
  // QuicConfig, which would default both to the same 16 KB) so an
  // operator can match them to their own path's BDP instead of guessing.
  QuicByteCount initial_stream_flow_control_window_bytes = 512 * 1024;

  // Initial per-session flow-control window. See
  // initial_stream_flow_control_window_bytes above.
  QuicByteCount initial_session_flow_control_window_bytes = 512 * 1024;

  // SO_RCVBUF/SO_SNDBUF set on every UDP socket quictun creates (one per
  // QUIC connection). Too small a value under load can cause packets to be
  // dropped by the kernel before quictun ever sees them -- indistinguishable
  // from real network loss to the congestion controller -- so this is
  // exposed for operators to size against their own concurrency/throughput
  // needs rather than trusting a single hardcoded default to fit everyone.
  QuicByteCount udp_socket_buffer_bytes = 1024 * 1024;

  // Manual startup-state tuning for BBR (see
  // SetQuictunStartupBandwidthHint() in quictun_connection_factory.h). If
  // startup_bandwidth_kbps > 0, bootstraps every new connection's
  // congestion controller (while still in STARTUP) with this assumed
  // bandwidth/RTT instead of letting it ramp up from scratch -- useful on
  // paths where the true available bandwidth is already known from
  // experience and the normal ramp-up is too slow to reach it (e.g. a
  // long-haul path with a large bandwidth-delay product). 0 (default)
  // disables this -- normal cold-start behavior, unaffected.
  int32_t startup_bandwidth_kbps = 0;
  int32_t startup_rtt_ms = 0;

  // Max concurrent bidirectional streams this endpoint will accept as
  // incoming from its peer -- i.e. what governs how many streams the
  // OTHER side can have open on one connection at once (see
  // QuicConfig::SetMaxBidirectionalStreamsToSend()). quictun's own
  // streams are always client-initiated, so in practice only the
  // SERVER's value actually constrains anything -- the client's own
  // copy of this flag is accepted for symmetry/documentation clarity
  // but never has anything to bite, since the server never opens a
  // stream to the client. Relevant specifically for --quic_conn pooling:
  // with quic_conn=N pool slots round-robining accepted TCPs, a single
  // pooled connection's concurrently-open stream count is the whole
  // pool's live TCP count divided across those N slots, not N itself --
  // a small N concentrates more of that load onto fewer connections,
  // making the shared per-connection cap more likely to matter than a
  // large N does. 100 matches QuicConfig's own real default
  // (kDefaultMaxStreamsPerConnection, quic_constants.h) -- quictun
  // otherwise never touches this at all, so this flag existing at its
  // default changes nothing from before it existed. Not a hard lifetime
  // cap: it's a sliding window that grows back by one every time an
  // existing stream closes (QuicStreamIdManager::OnStreamClosed()), so
  // it only actually blocks new streams while this many are open at
  // once, not after this many have ever been opened in total. A peer
  // that opens a stream beyond what's currently granted is treated as a
  // protocol violation -- not a per-stream rejection, but the *whole*
  // connection closing (QUIC_INVALID_STREAM_ID), taking every other
  // stream sharing it down too; confirmed via a real repro (see
  // testing/chaos/max_streams_test.py) that this fires correctly and
  // both endpoints survive it cleanly.
  int32_t max_streams_per_connection = 100;

  // Client-only: caps how many QUIC connections quictun_client keeps open
  // to --remote at once, multiplexing TCP tunnels onto them as streams once
  // that cap is reached instead of opening one QUIC connection per TCP
  // connection. 0 (default) means unlimited -- quictun's original
  // behavior, unchanged: every accepted --local connection gets its own
  // brand-new QUIC connection, exactly as if this option didn't exist. A
  // positive value pools: the client keeps at most quic_conn connections
  // open, round-robining new TCP connections across them (opening a new
  // stream on whichever one is selected) once all quic_conn slots are
  // already in use. See quictun_client_driver.h for the actual pooling
  // logic. Ignored by quictun_server, which is purely reactive to however
  // many streams a client legitimately opens on a connection -- see
  // QuictunServerConnection's class comment.
  // Client-only, set by quictun_client_bin.cc. Pooling is a property of how
  // the client assigns accepted TCP connections to QUIC connections; the
  // server sees only the streams that result and needs no matching setting.
  int32_t quic_conn = 0;
};

// Defines --key, --zero_rtt, --congestion_control, --so_txtime,
// --transparent, --idle_timeout_seconds,
// --initial_stream_flow_control_window_kb,
// --initial_session_flow_control_window_kb, --udp_socket_buffer_kb,
// --startup_bandwidth_kbps, --startup_rtt_ms,
// --max_streams_per_connection and reads their current values into a
// QuictunTuningOptions. Must be called after
// quiche::QuicheParseCommandLineFlags().
QuictunTuningOptions GetQuictunTuningOptionsFromFlags();

// Parses `value` as "host:port" or "[ipv6-literal]:port" into a
// QuicSocketAddress. Returns nullopt (after logging why) if `value` isn't a
// valid host:port string or the host isn't a literal IP address (quictun's
// flags are always IP:port, never DNS names).
std::optional<QuicSocketAddress> ParseQuictunSocketAddress(
    absl::string_view value);

// One "name = value" line in the startup banner below. `value` should
// already be formatted the way it's meant to be displayed (including any
// redaction -- see PrintQuictunStartupBanner()'s handling of --key).
struct QuictunConfigLine {
  std::string name;
  std::string value;
};

// Logs (once, at INFO) a human-readable startup banner: `binary_name`, this
// build's compile date/time (QuictunBuildTimestamp(), see
// quictun_build_info.h), and every active configuration value -- the
// binary-specific ones the caller supplies via `binary_specific_config`
// (e.g. --local/--remote for quictun_client, --listen/--target for
// quictun_server) followed by the flags common to both binaries, read from
// `options`. `--key` itself is never printed, only its length, so these
// logs are safe to paste into a bug report without leaking the shared
// secret. Call once from main(), after flags are parsed and validated.
void PrintQuictunStartupBanner(
    absl::string_view binary_name,
    const std::vector<QuictunConfigLine>& binary_specific_config,
    const QuictunTuningOptions& options);

// Just "<binary_name> (built <timestamp>)" -- the one line of
// PrintQuictunStartupBanner() above that doesn't need parsed flags to
// print. Call this first thing in main(), before flag parsing: unlike the
// full banner (which only ever runs once startup fully succeeds -- every
// flag-validation failure returns before reaching it, and
// --help/--helpfull exits from inside QuicheParseCommandLineFlags()
// itself), this makes the build identifiable even when the process never
// gets that far.
void PrintQuictunVersionLine(absl::string_view binary_name);

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_FLAGS_H_
