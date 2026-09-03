// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// quictun_client: listens for TCP connections on --local; for each one,
// opens a new QUIC connection to --remote and pumps bytes bidirectionally
// between the two.
//
// Usage: quictun_client --local=[::]:12948 --remote=<server-ip>:4433 --key='shared secret'

#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "quiche/quic/core/io/quic_default_event_loop.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/quic_default_clock.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/quictun_client_driver.h"
#include "quiche/quic/tools/quictun_connection_factory.h"
#include "quiche/quic/tools/quictun_flags.h"
#include "quiche/common/platform/api/quiche_command_line_flags.h"
#include "quiche/common/platform/api/quiche_system_event_loop.h"

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, local, "[::]:12948",
    "Address:port to listen for incoming TCP connections on. IPv6 "
    "wildcard addresses ([::]) also accept IPv4 traffic (dual-stack).");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, remote, "",
    "Address:port of the quictun_server to connect to for each accepted "
    "TCP connection. Required.");

// Client-only: quictun_server reads neither. It issues session tickets
// unconditionally (see quictun_certificate.h), so --zero_rtt only decides
// whether this client attempts resumption; and pooling is purely a property
// of how this client assigns accepted TCP connections to QUIC connections,
// which the server never needs to know.
DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, zero_rtt, true,
    "Attempt 0-RTT session resumption for QUIC connections made after the "
    "first, within this process's lifetime. This tool deliberately does not "
    "defend against 0-RTT replay; only rely on it on trusted/low-risk paths. "
    "Disable with --zero_rtt=false.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, quic_conn, 0,
    "Caps how many QUIC connections to keep open to --remote at once. Once "
    "that many are open, each further accepted TCP connection becomes an "
    "additional stream on one of them (picked round-robin) instead of "
    "opening another QUIC connection. 0 (default) means unlimited: every "
    "accepted TCP connection gets its own QUIC connection, its own UDP "
    "socket, and its own congestion-control state.");

#ifdef QUICTUN_COVERAGE_BUILD
// See quictun_server_bin.cc's identical block for why this exists --
// coverage-instrumented builds only, absent from every normal build.
extern "C" int __llvm_profile_write_file(void);
void FlushCoverageAndExit(int /*signum*/) {
  __llvm_profile_write_file();
  std::_Exit(0);
}
#endif

int main(int argc, char* argv[]) {
  // quic::socket_api::Send() (quic/core/io/socket.cc) is a bare ::send()
  // with no MSG_NOSIGNAL, so writing to the local --local TCP socket after
  // its peer already reset the connection -- routine whenever a download
  // being tunneled gets cancelled -- delivers SIGPIPE. Left at its default
  // disposition, that kills the whole process instantly with no log line
  // and no crash report, instead of the EPIPE status that should have just
  // closed that one tunnel (QuictunTunnel::SendComplete() already handles
  // a failed send correctly -- this is the only piece that was missing).
  signal(SIGPIPE, SIG_IGN);
#ifdef QUICTUN_COVERAGE_BUILD
  signal(SIGTERM, FlushCoverageAndExit);
#endif
  // Before anything else, including flag parsing: --help/--helpfull exit
  // from inside QuicheParseCommandLineFlags() below without ever reaching
  // PrintQuictunStartupBanner() (which needs parsed flags anyway), and
  // every flag-validation failure past that point returns before it too
  // -- this is the one build-identifying line guaranteed to show up no
  // matter how the process exits.
  quic::PrintQuictunVersionLine("quictun_client");
  quiche::QuicheSystemEventLoop system_event_loop("quictun_client");
  const char* usage =
      "Usage: quictun_client --local=[::]:12948 --remote=<server-ip>:4433 "
      "--key='shared secret'";
  std::vector<std::string> non_option_args =
      quiche::QuicheParseCommandLineFlags(usage, argc, argv);
  if (!non_option_args.empty()) {
    quiche::QuichePrintCommandLineFlagHelp(usage);
    return 1;
  }

  std::string local_flag = quiche::GetQuicheCommandLineFlag(FLAGS_local);
  std::optional<quic::QuicSocketAddress> local_address =
      quic::ParseQuictunSocketAddress(local_flag);
  if (!local_address.has_value()) {
    quiche::QuichePrintCommandLineFlagHelp(usage);
    return 1;
  }

  std::string remote_flag = quiche::GetQuicheCommandLineFlag(FLAGS_remote);
  std::optional<quic::QuicSocketAddress> remote_address =
      quic::ParseQuictunSocketAddress(remote_flag);
  if (!remote_address.has_value()) {
    quiche::QuichePrintCommandLineFlagHelp(usage);
    return 1;
  }

  quic::QuictunTuningOptions options = quic::GetQuictunTuningOptionsFromFlags();
  if (options.psk.empty()) {
    std::cerr << "--key is required" << std::endl;
    return 1;
  }
  options.zero_rtt = quiche::GetQuicheCommandLineFlag(FLAGS_zero_rtt);
  options.quic_conn = quiche::GetQuicheCommandLineFlag(FLAGS_quic_conn);

  quic::PrintQuictunStartupBanner(
      "quictun_client",
      {{"local", local_flag},
       {"remote", remote_flag},
       {"zero_rtt", options.zero_rtt ? "true" : "false"},
       {"quic_conn", options.quic_conn > 0 ? absl::StrCat(options.quic_conn)
                                           : "0 (unlimited)"}},
      options);

  std::unique_ptr<quic::QuicEventLoop> event_loop =
      quic::GetDefaultEventLoop()->Create(quic::QuicDefaultClock::Get());
  quic::QuictunClientDriver driver(event_loop.get(), *local_address,
                                   *remote_address, options);
  absl::Status status = driver.Start();
  if (!status.ok()) {
    std::cerr << "Failed to start quictun_client: " << status << std::endl;
    return 1;
  }

  while (true) {
    event_loop->RunEventLoopOnce(quic::QuicTime::Delta::FromMilliseconds(50));
    driver.CollectGarbage();
  }
}
