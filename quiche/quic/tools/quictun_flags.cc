// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_flags.h"

#include <algorithm>
#include <cstdint>
#include <iomanip>
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
    "Initial flow-control window advertised to the peer, in KiB. Since "
    "each connection carries exactly one stream, this is effectively the "
    "per-tunnel receive buffer budget; raise it for high-bandwidth-delay-"
    "product paths.");

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
  banner << std::string(kRuleWidth, '=');

  QUIC_LOG(INFO) << banner.str();
}

}  // namespace quic
