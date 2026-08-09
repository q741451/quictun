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
  bool zero_rtt = true;

  // "cubic" | "bbr" | "bbr2" | "bbr3". Applies to this endpoint's own send
  // direction only.
  std::string congestion_control = "cubic";

  // Whether to use SO_TXTIME (Linux packet pacing offload) on the UDP send
  // path. Falls back silently if the kernel doesn't support it.
  bool so_txtime = false;

  QuicTime::Delta idle_timeout = QuicTime::Delta::FromSeconds(60);

  // Initial per-stream flow-control window. Since each connection carries
  // exactly one stream, in practice the smaller of this and
  // initial_session_flow_control_window_bytes is what actually caps
  // throughput on high-bandwidth-delay-product paths -- raise both
  // together. Independently tunable from the session window (unlike
  // stock QuicConfig, which would default both to the same 16 KB) so an
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

  // Process-wide (not per-connection) overrides for the two thresholds
  // BbrSender::ShouldExitStartupDueToLoss() (bbr_sender.cc) uses to decide
  // BBRv1 should give up on STARTUP -- stop probing for more bandwidth and
  // settle for whatever it's already reached -- once a round sees enough
  // distinct loss-detection events AND the lost bytes exceed a fraction of
  // bytes in flight. See ApplyQuictunBbrStartupLossOverrides() in
  // quictun_connection_factory.h. Defaults here match QUICHE's own real
  // defaults exactly (2%, 8 events) -- i.e. quictun applies no override
  // at all unless one of these is explicitly changed, and the values
  // shown by --helpfull/the startup banner are always what's actually in
  // effect, not a sentinel. On a path with genuine baseline loss above 2%
  // that can still sustain a much higher real bandwidth once ramped, the
  // real default fires prematurely and the connection settles for far
  // less than the path can actually do -- raise loss_threshold_percent
  // (and/or full_loss_count) past the path's real loss rate to fix that.
  int32_t bbr_startup_loss_threshold_percent = 2;
  int32_t bbr_startup_full_loss_count = 8;
};

// Defines --key, --zero_rtt, --congestion_control, --so_txtime,
// --idle_timeout_seconds, --initial_stream_flow_control_window_kb,
// --initial_session_flow_control_window_kb, --udp_socket_buffer_kb,
// --startup_bandwidth_kbps, --startup_rtt_ms,
// --bbr_startup_loss_threshold_percent, --bbr_startup_full_loss_count and
// reads their current values into a QuictunTuningOptions. Must be called
// after quiche::QuicheParseCommandLineFlags().
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
