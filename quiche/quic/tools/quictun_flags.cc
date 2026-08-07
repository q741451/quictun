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
    bool, zero_rtt, true,
    "Enable 0-RTT session resumption for repeated QUIC connections made "
    "within this process's lifetime. This tool deliberately does not "
    "defend against 0-RTT replay; only rely on it on trusted/low-risk "
    "paths. Disable with --zero_rtt=false.");

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
    int32_t, idle_timeout_seconds, 60,
    "QUIC connection idle timeout, in seconds.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, initial_stream_flow_control_window_kb, 512,
    "Initial per-stream flow-control window advertised to the peer, in "
    "KiB. Independent of --initial_session_flow_control_window_kb -- the "
    "smaller of the two is what actually caps throughput in practice, "
    "since each connection carries exactly one stream. Raise both "
    "together for high-bandwidth-delay-product paths.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, initial_session_flow_control_window_kb, 512,
    "Initial per-session flow-control window advertised to the peer, in "
    "KiB. See --initial_stream_flow_control_window_kb.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, udp_socket_buffer_kb, 1024,
    "SO_RCVBUF/SO_SNDBUF size set on every UDP socket quictun creates (one "
    "per QUIC connection), in KiB. Applies to both the receive and send "
    "buffer. Too small a value under load can cause the kernel to drop "
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
    int32_t, bbr_startup_loss_threshold_percent, 2,
    "Process-wide. One of the two thresholds BBRv1 uses to decide 'give "
    "up probing for more bandwidth, I've hit loss-driven congestion' "
    "during STARTUP (BbrSender::ShouldExitStartupDueToLoss(), "
    "quic_bbr2_default_loss_threshold -- the name says bbr2 but BBRv1 "
    "reads the same flag). Default here (2, i.e. 2%) is QUICHE's own real "
    "default -- quictun applies no override unless you change this. On a "
    "path with genuine baseline loss above 2% that can still sustain a "
    "much higher real bandwidth once ramped, the default fires "
    "prematurely and settles for less than the path can actually do; "
    "raise this past the path's real loss rate to fix that. A value here "
    "is a percent (e.g. 50 for 50%), not a fraction.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, bbr_startup_full_loss_count, 8,
    "Process-wide. The other threshold paired with "
    "--bbr_startup_loss_threshold_percent -- minimum number of distinct "
    "loss-detection events (not lost packets) in one round before that "
    "threshold check even applies (quic_bbr2_default_startup_full_loss_"
    "count). Default here (8) is QUICHE's own real default -- quictun "
    "applies no override unless you change this.");

namespace quic {

QuictunTuningOptions GetQuictunTuningOptionsFromFlags() {
  QuictunTuningOptions options;
  options.psk = quiche::GetQuicheCommandLineFlag(FLAGS_key);
  options.zero_rtt = quiche::GetQuicheCommandLineFlag(FLAGS_zero_rtt);
  options.congestion_control =
      quiche::GetQuicheCommandLineFlag(FLAGS_congestion_control);
  options.so_txtime = quiche::GetQuicheCommandLineFlag(FLAGS_so_txtime);
  options.idle_timeout = QuicTime::Delta::FromSeconds(
      quiche::GetQuicheCommandLineFlag(FLAGS_idle_timeout_seconds));
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
  options.bbr_startup_loss_threshold_percent = quiche::GetQuicheCommandLineFlag(
      FLAGS_bbr_startup_loss_threshold_percent);
  options.bbr_startup_full_loss_count =
      quiche::GetQuicheCommandLineFlag(FLAGS_bbr_startup_full_loss_count);
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

void PrintQuictunStartupBanner(
    absl::string_view binary_name,
    const std::vector<QuictunConfigLine>& binary_specific_config,
    const QuictunTuningOptions& options) {
  std::vector<QuictunConfigLine> lines = binary_specific_config;
  lines.push_back(
      {"key", absl::StrCat("<redacted, ", options.psk.size(), " bytes>")});
  lines.push_back({"zero_rtt", options.zero_rtt ? "true" : "false"});
  lines.push_back({"congestion_control", options.congestion_control});
  lines.push_back({"so_txtime", options.so_txtime ? "true" : "false"});
  lines.push_back({"idle_timeout_seconds",
                    absl::StrCat(options.idle_timeout.ToSeconds())});
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
  // Unlike startup_bandwidth_kbps/startup_rtt_ms above (which are truly
  // off at 0, since QUICHE has no "assumed starting bandwidth" concept of
  // its own to fall back to), these two default to QUICHE's own real
  // defaults (see quictun_flags.h) -- always shown, not gated behind a
  // sentinel, so the banner always states what's actually in effect.
  lines.push_back({"bbr_startup_loss_threshold_percent",
                    absl::StrCat(options.bbr_startup_loss_threshold_percent)});
  lines.push_back({"bbr_startup_full_loss_count",
                    absl::StrCat(options.bbr_startup_full_loss_count)});

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
