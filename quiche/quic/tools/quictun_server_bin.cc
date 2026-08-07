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

  std::string target_flag = quiche::GetQuicheCommandLineFlag(FLAGS_target);
  std::optional<quic::QuicSocketAddress> target_address =
      quic::ParseQuictunSocketAddress(target_flag);
  if (!target_address.has_value()) {
    quiche::QuichePrintCommandLineFlagHelp(usage);
    return 1;
  }

  quic::QuictunTuningOptions options = quic::GetQuictunTuningOptionsFromFlags();
  if (options.psk.empty()) {
    std::cerr << "--key is required" << std::endl;
    return 1;
  }
  // Process-wide; must run before any connection is created, and after
  // flag parsing since it reads --bbr_startup_loss_threshold_percent/
  // --bbr_startup_full_loss_count.
  quic::ApplyQuictunBbrStartupLossOverrides(
      options.bbr_startup_loss_threshold_percent,
      options.bbr_startup_full_loss_count);

  quic::PrintQuictunStartupBanner(
      "quictun_server",
      {{"listen", listen_flag}, {"target", target_flag}}, options);

  std::unique_ptr<quic::QuicEventLoop> event_loop =
      quic::GetDefaultEventLoop()->Create(quic::QuicDefaultClock::Get());
  quic::QuictunServerDriver driver(event_loop.get(), *listen_address,
                                   *target_address, options);
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
