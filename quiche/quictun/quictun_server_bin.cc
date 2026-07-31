// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// quictun-server: accepts quictun-client tunnels over QUIC and forwards each
// proxied stream to a fixed local TCP target, analogous to
// `kcptun-server -l <listen> -t <target>` but with QUIC (via
// google/quiche's WebTransport-over-HTTP/3) standing in for KCP+smux.

#include <csignal>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

#include "absl/log/globals.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/crypto/quic_crypto_server_config.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_tag.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/quic_server.h"
#include "quiche/quictun/cert_util.h"
#include "quiche/quictun/quictun_auth.h"
#include "quiche/quictun/quictun_backend.h"
#include "quiche/quictun/tcp_util.h"
#include "quiche/common/platform/api/quiche_command_line_flags.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_system_event_loop.h"

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, listen, "0.0.0.0:4433",
    "QUIC/UDP listen address (host:port).");
DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, target, "127.0.0.1:12948",
    "TCP address (host:port) that every proxied stream is forwarded to.");
DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, key, "it's a secret",
    "Pre-shared key; overridden by the QUICTUN_KEY environment variable "
    "if set.");
DEFINE_QUICHE_COMMAND_LINE_FLAG(bool, quiet, false,
                                "Suppress per-stream open/close log lines.");
DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, cert, "quictun_cert.pem",
    "Path to the server's TLS certificate (PEM); auto-generated "
    "(self-signed) on first run if missing. Trust comes from --key, not "
    "from this certificate's identity -- see quictun_auth.h.");
DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, certkey, "quictun_key.pem",
    "Path to the private key (PEM) matching --cert; auto-generated "
    "alongside it if missing.");

namespace quictun {
namespace {

// See the matching comment in quictun_client_bin.cc: quiche's bare
// QuicConfig() defaults both flow control windows to 16 KB (both sides
// negotiate down to the smaller advertised window, so these must match the
// client's), and defaults congestion control to Cubic rather than BBR/BBRv2
// -- request BBRv2 explicitly to match what Chrome's real-world QUIC peers
// (e.g. Google's video-serving infrastructure) actually run.
quic::QuicConfig BuildTunedQuicConfig() {
  quic::QuicConfig config;
  constexpr uint64_t kStreamWindow = 6 * 1024 * 1024;    // 6 MB
  constexpr uint64_t kSessionWindow = 15 * 1024 * 1024;  // 15 MB
  config.SetInitialStreamFlowControlWindowToSend(kStreamWindow);
  config.SetInitialSessionFlowControlWindowToSend(kSessionWindow);
  quic::QuicTagVector options{quic::kB2ON};
  config.SetConnectionOptionsToSend(options);
  config.SetClientConnectionOptions(options);
  return config;
}

int Main(int argc, char** argv) {
  // See the matching comment in quictun_client_bin.cc: TunnelPump's writes
  // to the proxied TCP target socket can hit a reset connection under load,
  // and an unhandled SIGPIPE from that would otherwise kill the whole
  // server process instead of just closing that one stream.
  signal(SIGPIPE, SIG_IGN);
  // See the matching comment in quictun_client_bin.cc.
  absl::SetStderrThreshold(absl::LogSeverityAtLeast::kInfo);
  quiche::QuicheSystemEventLoop system_event_loop("quictun-server");
  const char* usage = "Usage: quictun_server [options]";
  quiche::QuicheParseCommandLineFlags(usage, argc, argv);

  std::string key = quiche::GetQuicheCommandLineFlag(FLAGS_key);
  if (const char* env_key = std::getenv("QUICTUN_KEY");
      env_key != nullptr && env_key[0] != '\0') {
    key = env_key;
  }
  bool quiet = quiche::GetQuicheCommandLineFlag(FLAGS_quiet);

  absl::StatusOr<quic::QuicSocketAddress> listen_address =
      ResolveHostPort(quiche::GetQuicheCommandLineFlag(FLAGS_listen));
  if (!listen_address.ok()) {
    QUICHE_LOG(ERROR) << listen_address.status();
    return 1;
  }
  absl::StatusOr<quic::QuicSocketAddress> target_address =
      ResolveHostPort(quiche::GetQuicheCommandLineFlag(FLAGS_target));
  if (!target_address.ok()) {
    QUICHE_LOG(ERROR) << target_address.status();
    return 1;
  }

  absl::StatusOr<std::unique_ptr<quic::ProofSource>> proof_source =
      LoadOrCreateProofSource(quiche::GetQuicheCommandLineFlag(FLAGS_cert),
                              quiche::GetQuicheCommandLineFlag(FLAGS_certkey));
  if (!proof_source.ok()) {
    QUICHE_LOG(ERROR) << "certificate setup failed: " << proof_source.status();
    return 1;
  }

  QuictunBackend backend(*target_address, ComputeAuthToken(key), quiet);
  quic::QuicServer server(*std::move(proof_source), /*proof_verifier=*/nullptr,
                          BuildTunedQuicConfig(),
                          quic::QuicCryptoServerConfig::ConfigOptions(),
                          quic::AllSupportedVersions(), &backend,
                          quic::kQuicDefaultConnectionIdLength);
  backend.SetServer(&server);

  if (!server.CreateUDPSocketAndListen(*listen_address)) {
    QUICHE_LOG(ERROR) << "failed to listen on " << *listen_address;
    return 1;
  }
  QUICHE_LOG(INFO) << "quictun-server listening on " << *listen_address
                   << ", forwarding to " << *target_address;
  server.HandleEventsForever();
  return 0;
}

}  // namespace
}  // namespace quictun

int main(int argc, char** argv) { return quictun::Main(argc, argv); }
