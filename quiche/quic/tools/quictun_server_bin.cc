// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// quictun_server: tunnels raw TCP connections over raw QUIC (no HTTP/3).
// Listens for QUIC connections on --listen and, for each one, opens a TCP
// connection to --target and pumps bytes bidirectionally between the two.
//
// Usage: quictun_server --listen=[::]:4433 --target=127.0.0.1:12948 --key='shared secret'

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
#include "quiche/quic/tools/quictun_connection_factory.h"
#include "quiche/quic/tools/quictun_flags.h"
#include "quiche/quic/tools/quictun_server_driver.h"
#include "quiche/common/platform/api/quiche_command_line_flags.h"
#include "quiche/common/platform/api/quiche_system_event_loop.h"

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, listen, "[::]:4433",
    "Address:port to listen for incoming QUIC (UDP) connections on. IPv6 "
    "wildcard addresses ([::]) also accept IPv4 traffic (dual-stack).");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, target, "",
    "Address:port of the TCP server to connect to for each accepted "
    "tunnel. Required.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, max_new_connections_per_event_loop, 100,
    "Caps how many brand-new connections quictun_server will create per "
    "event-loop iteration (~every 50ms); packets that would create "
    "another past that are dropped once the budget hits zero for that "
    "tick (a legitimate client's own QUIC handshake retransmission just "
    "retries, so this only spreads out genuine bursts, never silently "
    "drops them for good). Bounds how much CPU/memory a flood of "
    "spoofed-source garbage packets can force per tick. Default (100) "
    "matches real QUICHE's own "
    "QuicBufferedPacketStore::kDefaultMaxConnectionsInStore.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, max_concurrent_connections, 5000,
    "Hard cap on how many connections (established or mid-handshake) "
    "quictun_server will have open at once; packets that would create "
    "another past that are dropped. Each connection holds at least one "
    "dedicated UDP socket, so this bounds fd/memory exhaustion from a "
    "flood of forged connection attempts instead of relying on the OS "
    "fd limit to be the thing that eventually says no. Default (5000) "
    "is meant to be generous relative to any realistic legitimate "
    "load.");

#ifdef QUICTUN_COVERAGE_BUILD
// Coverage-instrumented builds only (--copt=-DQUICTUN_COVERAGE_BUILD,
// alongside -fprofile-instr-generate) -- absent, and this whole block does
// not exist, in every normal build. quictun_server has no natural
// clean-exit path (its event loop below runs forever) and installs no
// SIGTERM handler, so a coverage test harness's terminate()/kill() calls --
// the only way anything ever stops a quictun process -- leave zero durable
// profile data on disk: confirmed empirically (0-byte .profraw even with
// -fprofile-continuous, which doesn't appear to actually engage in this
// clang snapshot). __llvm_profile_write_file() is compiler-rt's profiling
// runtime, only linked in when built with -fprofile-instr-generate, hence
// this being gated on the same macro rather than always declared.
extern "C" int __llvm_profile_write_file(void);
void FlushCoverageAndExit(int /*signum*/) {
  __llvm_profile_write_file();
  std::_Exit(0);
}
#endif

int main(int argc, char* argv[]) {
  // quic::socket_api::Send() (quic/core/io/socket.cc) is a bare ::send()
  // with no MSG_NOSIGNAL, so writing to the local --target TCP socket
  // after its peer already reset the connection -- routine whenever a
  // download being tunneled gets cancelled -- delivers SIGPIPE. Left at
  // its default disposition, that kills the whole process instantly with
  // no log line and no crash report, instead of the EPIPE status that
  // should have just closed that one tunnel (QuictunTunnel::SendComplete()
  // already handles a failed send correctly -- this is the only piece
  // that was missing).
  signal(SIGPIPE, SIG_IGN);
#ifdef QUICTUN_COVERAGE_BUILD
  signal(SIGTERM, FlushCoverageAndExit);
#endif
  // See quictun_client_bin.cc's identical call for why this comes before
  // everything else, including flag parsing.
  quic::PrintQuictunVersionLine("quictun_server");
  quiche::QuicheSystemEventLoop system_event_loop("quictun_server");
  const char* usage =
      "Usage: quictun_server --listen=[::]:4433 --target=127.0.0.1:12948 "
      "--key='shared secret'";
  std::vector<std::string> non_option_args =
      quiche::QuicheParseCommandLineFlags(usage, argc, argv);
  if (!non_option_args.empty()) {
    quiche::QuichePrintCommandLineFlagHelp(usage);
    return 1;
  }

  std::string listen_flag = quiche::GetQuicheCommandLineFlag(FLAGS_listen);
  std::optional<quic::QuicSocketAddress> listen_address =
      quic::ParseQuictunSocketAddress(listen_flag);
  if (!listen_address.has_value()) {
    quiche::QuichePrintCommandLineFlagHelp(usage);
    return 1;
  }

  quic::QuictunTuningOptions options = quic::GetQuictunTuningOptionsFromFlags();
  if (options.psk.empty()) {
    std::cerr << "--key is required" << std::endl;
    return 1;
  }

  std::string target_flag = quiche::GetQuicheCommandLineFlag(FLAGS_target);
  std::optional<quic::QuicSocketAddress> target_address;
  if (options.transparent) {
    // --target and --transparent speak incompatible wire formats (see
    // --transparent's own help text) -- refuse to guess which one was
    // meant rather than silently ignoring one of them.
    if (!target_flag.empty()) {
      std::cerr << "--target must not be set when --transparent is enabled "
                   "-- the destination is captured per-connection instead"
                << std::endl;
      return 1;
    }
  } else {
    target_address = quic::ParseQuictunSocketAddress(target_flag);
    if (!target_address.has_value()) {
      quiche::QuichePrintCommandLineFlagHelp(usage);
      return 1;
    }
  }
  int32_t max_new_connections_per_event_loop = quiche::GetQuicheCommandLineFlag(
      FLAGS_max_new_connections_per_event_loop);
  int32_t max_concurrent_connections =
      quiche::GetQuicheCommandLineFlag(FLAGS_max_concurrent_connections);

  quic::PrintQuictunStartupBanner(
      "quictun_server",
      {{"listen", listen_flag},
       {"target", options.transparent ? "(transparent mode)" : target_flag},
       {"max_new_connections_per_event_loop",
        absl::StrCat(max_new_connections_per_event_loop)},
       {"max_concurrent_connections",
        absl::StrCat(max_concurrent_connections)}},
      options);

  std::unique_ptr<quic::QuicEventLoop> event_loop =
      quic::GetDefaultEventLoop()->Create(quic::QuicDefaultClock::Get());
  quic::QuictunServerDriver driver(event_loop.get(), *listen_address,
                                   target_address, options,
                                   max_new_connections_per_event_loop,
                                   max_concurrent_connections);
  absl::Status status = driver.Start();
  if (!status.ok()) {
    std::cerr << "Failed to start quictun_server: " << status << std::endl;
    return 1;
  }

  while (true) {
    event_loop->RunEventLoopOnce(quic::QuicTime::Delta::FromMilliseconds(50));
    driver.CollectGarbage();
  }
}
