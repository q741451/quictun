// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// quictun_client: listens for TCP connections on --local; for each one,
// opens a new QUIC connection to --remote and pumps bytes bidirectionally
// between the two.
//
// Usage: quictun_client --local=[::]:12948 --remote=<server-ip>:4433 --key='shared secret'

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
#include "quiche/quic/tools/quictun_client_driver.h"
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

int main(int argc, char* argv[]) {
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

  std::optional<quic::QuicSocketAddress> local_address =
      quic::ParseQuictunSocketAddress(
          quiche::GetQuicheCommandLineFlag(FLAGS_local));
  if (!local_address.has_value()) {
    quiche::QuichePrintCommandLineFlagHelp(usage);
    return 1;
  }

  std::optional<quic::QuicSocketAddress> remote_address =
      quic::ParseQuictunSocketAddress(
          quiche::GetQuicheCommandLineFlag(FLAGS_remote));
  if (!remote_address.has_value()) {
    quiche::QuichePrintCommandLineFlagHelp(usage);
    return 1;
  }

  quic::QuictunTuningOptions options = quic::GetQuictunTuningOptionsFromFlags();
  if (options.psk.empty()) {
    std::cerr << "--key is required" << std::endl;
    return 1;
  }

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
