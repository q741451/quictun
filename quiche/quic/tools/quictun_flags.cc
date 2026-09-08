// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_flags.h"

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_server_id.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/quictun_build_info.h"
#include "quiche/common/platform/api/quiche_command_line_flags.h"

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, key, "",
    "Shared secret checked at the start of every tunnel, before any data "
    "is relayed. Required. The two endpoints must be configured with the "
    "identical value.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, congestion_control, "cubic",
    "Congestion control algorithm for this endpoint's own send direction: "
    "one of cubic, bbr, bbr2, bbr3.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, so_txtime, false,
    "Use SO_TXTIME (Linux packet pacing offload) for the UDP send path. "
    "Off by default; falls back silently if the kernel doesn't support "
    "it.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, transparent, false,
    "Transparent-proxy mode (Linux only). quictun_client captures each "
    "accepted TCP connection's original destination via SO_ORIGINAL_DST "
    "(populated by an external iptables/nftables REDIRECT rule the "
    "operator sets up separately -- quictun itself never touches "
    "netfilter config) instead of always tunneling to one fixed address; "
    "quictun_server connects out to that per-stream destination instead "
    "of --target. Mutually exclusive with --target -- setting both is a "
    "startup error, since the two modes speak incompatible wire formats "
    "(--target's existing mode has zero framing after the --key preamble; "
    "transparent mode prepends an address header). Both quictun_client "
    "and quictun_server must be started with the same value, the same as "
    "--key. false (default) is a no-op -- normal port-forward behavior, "
    "unchanged.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, idle_timeout_seconds, 60,
    "QUIC connection idle timeout, in seconds: how long a connection may go "
    "without receiving anything from the peer before it is torn down. While "
    "the peer is alive the client's own 15s keepalive PINGs keep resetting "
    "this, so in practice it only fires once the peer really is gone -- it "
    "is what bounds how long a vanished peer's connection (its UDP socket, "
    "its session state, and every tunnel's target-side TCP socket) is held "
    "before being reclaimed, so keep it short. Does NOT govern how long a "
    "quiet tunnel may stay open -- that is --tcp_idle_timeout_seconds.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, tcp_idle_timeout_seconds, 86400,
    "Per-tunnel idle timeout, in seconds: one tunnel with no real data in "
    "either direction for this long is closed, leaving the QUIC connection "
    "carrying it -- and every other tunnel on it -- untouched. Independent "
    "of --idle_timeout_seconds, which reclaims connections whose peer has "
    "vanished; this is application policy for a tunnel that is merely quiet, "
    "so the default (24h) is deliberately lax enough never to cut a "
    "connection that is simply idle rather than dead. Both quictun_client "
    "and quictun_server apply their own copy of this to the tunnels they "
    "hold, so set it the same on both ends.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, tcp_stalled_timeout_seconds, 180,
    "--tcp_idle_timeout_seconds, but for a tunnel that is stalled rather "
    "than merely quiet: one holding buffered data it cannot hand on, "
    "because the peer stopped reading the QUIC stream or the target TCP "
    "socket stopped draining. That costs flow-control credit and memory the "
    "whole QUIC connection shares, so enough such tunnels wedge every other "
    "tunnel on it -- hence a much shorter default. Any progress in either "
    "direction restarts the clock, so this cuts a stalled transfer, never a "
    "slow one. Capped at --tcp_idle_timeout_seconds. Set it the same on "
    "both ends.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, initial_stream_flow_control_window_kb, 512,
    "Initial per-stream flow-control window advertised to the peer, in "
    "KiB. Independent of --initial_session_flow_control_window_kb -- with "
    "this being per stream, it is what caps a single tunnel's throughput; "
    "since several tunnels share a connection, the session window also "
    "caps their combined total. Raise both together for high-bandwidth-"
    "delay-product paths.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, initial_session_flow_control_window_kb, 512,
    "Initial per-session flow-control window advertised to the peer, in "
    "KiB. See --initial_stream_flow_control_window_kb.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, udp_socket_buffer_kb, 1024,
    "SO_RCVBUF/SO_SNDBUF size set on every UDP socket quictun creates "
    "(--udp_socket of them on the client, one on the server), in KiB. "
    "Applies to both the receive and send buffer. Too small a value under "
    "load can cause the kernel to drop "
    "packets before quictun ever sees them, which looks like network loss "
    "to the congestion controller; raise it if system-wide UDP receive "
    "buffer drops (visible via /proc/net/snmp's Udp: RcvbufErrors column, "
    "or nstat -az UdpRcvbufErrors) climb during a transfer.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, startup_bandwidth_kbps, 0,
    "If > 0, bootstrap every new connection's congestion controller with "
    "this assumed starting bandwidth (Kbps, i.e. kilobits/sec -- NOT KB/s "
    "or bytes) instead of ramping up from scratch. Only affects the "
    "controller while still in STARTUP; has no effect once a connection "
    "reaches steady state. 0 (default) disables this -- normal cold-start "
    "behavior.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, startup_rtt_ms, 0,
    "Assumed starting RTT (milliseconds) paired with "
    "--startup_bandwidth_kbps -- only used, and only meaningful, if that "
    "flag is also > 0. 0 (default) falls back to QUICHE's own initial RTT "
    "guess (100ms).");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, max_streams_per_connection, 10000,
    "Max concurrent bidirectional streams this endpoint will accept as "
    "incoming from its peer at once -- in practice only the server's "
    "value does anything, since quictun's streams are always client-"
    "initiated. This is quictun's concurrency ceiling: every accepted TCP "
    "connection is a stream on one of the client's --udp_socket x "
    "--conn_per_udp connections, so at most their product times this many "
    "can be open at once. Hitting it does not fail cleanly -- a TCP that "
    "lands on an already-full connection queues there -- so the default "
    "(10000) sits well above any plausible real load rather than at "
    "QUICHE's own default of 100. Raising it costs nothing by itself: it "
    "is a number sent in a transport parameter, and a stream only occupies "
    "memory once actually opened. Not a hard lifetime cap: it's a sliding "
    "window that grows back by one every time an existing stream closes, "
    "so it only "
    "blocks new streams while this many are open at once. A peer that "
    "opens a stream beyond what's currently granted anyway is a protocol "
    "violation -- not a per-stream rejection but the whole connection "
    "closing, taking every other stream sharing it down too.");

namespace quic {

QuictunTuningOptions GetQuictunTuningOptionsFromFlags() {
  QuictunTuningOptions options;
  options.psk = quiche::GetQuicheCommandLineFlag(FLAGS_key);
  options.congestion_control =
      quiche::GetQuicheCommandLineFlag(FLAGS_congestion_control);
  options.so_txtime = quiche::GetQuicheCommandLineFlag(FLAGS_so_txtime);
  options.transparent = quiche::GetQuicheCommandLineFlag(FLAGS_transparent);
  options.idle_timeout = QuicTime::Delta::FromSeconds(
      quiche::GetQuicheCommandLineFlag(FLAGS_idle_timeout_seconds));
  options.tcp_idle_timeout = QuicTime::Delta::FromSeconds(
      quiche::GetQuicheCommandLineFlag(FLAGS_tcp_idle_timeout_seconds));
  options.tcp_stalled_timeout = QuicTime::Delta::FromSeconds(
      quiche::GetQuicheCommandLineFlag(FLAGS_tcp_stalled_timeout_seconds));
  options.initial_stream_flow_control_window_bytes =
      static_cast<QuicByteCount>(quiche::GetQuicheCommandLineFlag(
          FLAGS_initial_stream_flow_control_window_kb)) *
      1024;
  options.initial_session_flow_control_window_bytes =
      static_cast<QuicByteCount>(quiche::GetQuicheCommandLineFlag(
          FLAGS_initial_session_flow_control_window_kb)) *
      1024;
  options.udp_socket_buffer_bytes =
      static_cast<QuicByteCount>(
          quiche::GetQuicheCommandLineFlag(FLAGS_udp_socket_buffer_kb)) *
      1024;
  options.startup_bandwidth_kbps =
      quiche::GetQuicheCommandLineFlag(FLAGS_startup_bandwidth_kbps);
  options.startup_rtt_ms =
      quiche::GetQuicheCommandLineFlag(FLAGS_startup_rtt_ms);
  options.max_streams_per_connection =
      quiche::GetQuicheCommandLineFlag(FLAGS_max_streams_per_connection);
  return options;
}

std::optional<QuicSocketAddress> ParseQuictunSocketAddress(
    absl::string_view value) {
  std::optional<QuicServerId> server_id =
      QuicServerId::ParseFromHostPortString(value);
  if (!server_id.has_value()) {
    QUIC_LOG(ERROR) << "Could not parse \"" << value
                    << "\" as a host:port address";
    return std::nullopt;
  }

  // QuicServerId::ParseFromHostPortString() returns the host component
  // exactly as it appeared in the input, brackets included for IPv6
  // literals (e.g. "[::]") -- strip them before handing it to
  // QuicIpAddress::FromString(), which expects the bare literal.
  std::string host = server_id->host();
  if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
    host = host.substr(1, host.size() - 2);
  }

  QuicIpAddress ip;
  if (!ip.FromString(host)) {
    QUIC_LOG(ERROR) << "\"" << host
                    << "\" is not a literal IP address (DNS names are not "
                       "supported)";
    return std::nullopt;
  }

  return QuicSocketAddress(ip, server_id->port());
}

void PrintQuictunVersionLine(absl::string_view binary_name) {
  // Same std::cerr-not-QUIC_LOG rationale as PrintQuictunStartupBanner()
  // below -- plus this runs before quiche's flag parsing (which is what
  // calls absl::InitializeLog()), so QUIC_LOG isn't even set up yet at
  // this point regardless.
  std::cerr << binary_name << "  (built " << QuictunBuildTimestamp() << ")\n";
}

void PrintQuictunStartupBanner(
    absl::string_view binary_name,
    const std::vector<QuictunConfigLine>& binary_specific_config,
    const QuictunTuningOptions& options) {
  std::vector<QuictunConfigLine> lines = binary_specific_config;
  lines.push_back(
      {"key", absl::StrCat("<redacted, ", options.psk.size(), " bytes>")});
  lines.push_back({"congestion_control", options.congestion_control});
  lines.push_back({"so_txtime", options.so_txtime ? "true" : "false"});
  lines.push_back({"transparent", options.transparent ? "true" : "false"});
  lines.push_back({"idle_timeout_seconds",
                    absl::StrCat(options.idle_timeout.ToSeconds())});
  lines.push_back({"tcp_idle_timeout_seconds",
                    absl::StrCat(options.tcp_idle_timeout.ToSeconds())});
  lines.push_back({"tcp_stalled_timeout_seconds",
                    absl::StrCat(options.tcp_stalled_timeout.ToSeconds())});
  lines.push_back(
      {"initial_stream_flow_control_window_kb",
       absl::StrCat(options.initial_stream_flow_control_window_bytes /
                     1024)});
  lines.push_back(
      {"initial_session_flow_control_window_kb",
       absl::StrCat(options.initial_session_flow_control_window_bytes /
                     1024)});
  lines.push_back({"udp_socket_buffer_kb",
                    absl::StrCat(options.udp_socket_buffer_bytes / 1024)});
  if (options.startup_bandwidth_kbps > 0) {
    lines.push_back({"startup_bandwidth_kbps",
                      absl::StrCat(options.startup_bandwidth_kbps)});
    lines.push_back(
        {"startup_rtt_ms",
         absl::StrCat(options.startup_rtt_ms > 0 ? options.startup_rtt_ms
                                                  : 100)});
  }
  lines.push_back({"max_streams_per_connection",
                    absl::StrCat(options.max_streams_per_connection)});

  size_t name_width = 0;
  for (const QuictunConfigLine& line : lines) {
    name_width = std::max(name_width, line.name.size());
  }
  constexpr int kRuleWidth = 66;

  std::ostringstream banner;
  banner << "\n"
         << std::string(kRuleWidth, '=') << "\n"
         << binary_name << "  (built " << QuictunBuildTimestamp() << ")\n"
         << std::string(kRuleWidth, '-') << "\n";
  for (const QuictunConfigLine& line : lines) {
    banner << "  " << std::left << std::setw(static_cast<int>(name_width))
           << line.name << "  = " << line.value << "\n";
  }
  banner << std::string(kRuleWidth, '=') << "\n";

  // Deliberately std::cerr, not QUIC_LOG(INFO): this banner is an operator-
  // facing "here's what's actually running" confirmation, not a leveled
  // debug log. quiche's flag parsing calls absl::InitializeLog() before
  // this runs, and absl's default stderr threshold after that point is
  // WARNING -- QUIC_LOG(INFO) here would silently disappear unless the
  // operator already knew to pass --stderrthreshold=0, defeating the
  // point of a banner meant to be visible by default.
  std::cerr << banner.str();
}

}  // namespace quic
