// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// quictun-client: forwards a local TCP port to a quictun-server over QUIC,
// analogous to `kcptun -l <local> -r <remote>` but with QUIC (via
// google/quiche's WebTransport-over-HTTP/3) standing in for KCP+smux.

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/log/globals.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/io/quic_default_event_loop.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_default_clock.h"
#include "quiche/quic/core/quic_server_id.h"
#include "quiche/quic/core/quic_tag.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/fake_proof_verifier.h"
#include "quiche/quic/tools/web_transport_only_client.h"
#include "quiche/quictun/quictun_auth.h"
#include "quiche/quictun/tcp_util.h"
#include "quiche/quictun/tunnel_pump.h"
#include "quiche/quictun/session_visitors.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_command_line_flags.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_system_event_loop.h"
#include "quiche/web_transport/web_transport.h"

DEFINE_QUICHE_COMMAND_LINE_FLAG(std::string, local, "127.0.0.1:12948",
                                "Local TCP listen address (host:port).");
DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, remote, "",
    "quictun-server address (host:port). Required.");
DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, key, "it's a secret",
    "Pre-shared key; overridden by the QUICTUN_KEY environment variable "
    "if set.");
DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, conn, 1, "Number of parallel QUIC sessions to the server.");
DEFINE_QUICHE_COMMAND_LINE_FLAG(bool, quiet, false,
                                "Suppress per-stream open/close log lines.");

namespace quictun {
namespace {

struct ClientOptions {
  quic::QuicSocketAddress server_address;
  quic::QuicServerId server_id;
  std::string auth_token;
  bool quiet;
};

// quiche's bare QuicConfig() defaults both the per-stream and per-session
// flow control windows to kMinimumFlowControlSendWindow (16 KB), which caps
// throughput at roughly window/RTT. The values below match Chrome's own
// net/quic/quic_context.cc constants exactly: kQuicStreamMaxRecvWindowSize
// (6 MB) and kQuicSessionMaxRecvWindowSize (15 MB). The server
// (quictun_server_bin.cc) must use matching values, since the smaller side
// of any given stream/session negotiation wins.
//
// Separately: quiche's own connection default congestion control is Cubic
// (see GetDefaultCongestionControlType() in quic_connection.cc) unless BBR
// is requested via a connection option -- it does NOT default to BBR/BBRv2
// the way Google's production QUIC servers (and by extension what Chrome
// talks to) typically do. That default-algorithm gap, not a code bug, is
// almost certainly the dominant cause of a large real-network throughput
// gap vs. Chrome/YouTube (loopback tests with near-zero RTT hit 100+ Mbps
// with the exact same TunnelPump code, so the pumping/chunking logic is not
// the bottleneck). Request BBRv2 (tag B2ON) explicitly to match.
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

struct ManagedSession {
  std::unique_ptr<quic::WebTransportOnlyClient> client;
  ClientTunnelSessionVisitor* visitor = nullptr;  // Owned by `client`.
};

// Blocks (retrying once a second) until a new QUIC/WebTransport session to
// the server is established. Mirrors kcptun client's waitConn().
ManagedSession DialUntilConnected(quic::QuicEventLoop* event_loop,
                                  const ClientOptions& options) {
  while (true) {
    auto client = std::make_unique<quic::WebTransportOnlyClient>(
        options.server_address, options.server_id,
        quic::CurrentSupportedVersionsWithTls(), BuildTunedQuicConfig(),
        event_loop, /*network_helper=*/nullptr,
        std::make_unique<quic::FakeProofVerifier>(),
        /*session_cache=*/nullptr);

    quiche::HttpHeaderBlock extra_headers;
    extra_headers[kAuthHeader] = options.auth_token;

    ClientTunnelSessionVisitor* visitor_ptr = nullptr;
    absl::Status status = client->ConnectSync(
        "/quictun",
        [&](webtransport::Session* session) {
          auto visitor = std::make_unique<ClientTunnelSessionVisitor>(session);
          visitor_ptr = visitor.get();
          return visitor;
        },
        /*subprotocols=*/{}, extra_headers);
    if (status.ok()) {
      if (!options.quiet) {
        QUICHE_LOG(INFO) << "connected to " << options.server_address;
      }
      return ManagedSession{std::move(client), visitor_ptr};
    }
    if (!options.quiet) {
      QUICHE_LOG(INFO) << "re-connecting: " << status;
    }
    absl::SleepFor(absl::Seconds(1));
  }
}

// Accepts local TCP connections and round-robins them across the pool of
// QUIC sessions, opening one new outgoing WebTransport stream per
// connection. Mirrors kcptun client's per-connection accept loop.
class LocalListener : public quic::QuicSocketEventListener {
 public:
  LocalListener(quic::QuicEventLoop* event_loop, quic::SocketFd listen_fd,
               std::vector<ManagedSession>* sessions,
               const ClientOptions& options)
      : event_loop_(event_loop),
        listen_fd_(listen_fd),
        sessions_(sessions),
        options_(options) {
    event_loop_->RegisterSocket(listen_fd_, quic::kSocketEventReadable, this);
  }

  void OnSocketEvent(quic::QuicEventLoop* /*event_loop*/,
                     quic::SocketFd /*fd*/,
                     quic::QuicSocketEventMask events) override {
    if (events & quic::kSocketEventReadable) {
      while (true) {
        absl::StatusOr<quic::socket_api::AcceptResult> accepted =
            quic::socket_api::Accept(listen_fd_, /*blocking=*/false);
        if (!accepted.ok()) {
          if (!absl::IsUnavailable(accepted.status()) && !options_.quiet) {
            QUICHE_LOG(ERROR) << "accept() failed: " << accepted.status();
          }
          break;
        }
        HandleAccepted(accepted->fd);
      }
    }
    // On event loops without edge-triggered semantics, a socket's
    // registration is one-shot and lapses after it fires once; it must be
    // re-armed after every callback or subsequent connections are silently
    // never accept()-ed (they just sit in the kernel's backlog forever).
    if (!event_loop_->SupportsEdgeTriggered()) {
      event_loop_->RearmSocket(listen_fd_, quic::kSocketEventReadable);
    }
  }

 private:
  void HandleAccepted(quic::SocketFd fd) {
    size_t idx = round_robin_ % sessions_->size();
    round_robin_++;
    ManagedSession& mux = (*sessions_)[idx];
    if (mux.visitor->closed()) {
      mux = DialUntilConnected(event_loop_, options_);
    }
    webtransport::Session* session = mux.visitor->session();
    if (!session->CanOpenNextOutgoingBidirectionalStream()) {
      if (!options_.quiet) {
        QUICHE_LOG(INFO) << "stream flow control exhausted, dropping connection";
      }
      quic::socket_api::Close(fd);
      return;
    }
    webtransport::Stream* stream = session->OpenOutgoingBidirectionalStream();
    if (!options_.quiet) {
      QUICHE_LOG(INFO) << "stream opened";
    }
    auto pump = std::make_unique<TunnelPump>(event_loop_, fd, stream,
                                             options_.quiet,
                                             /*connecting=*/false);
    stream->SetVisitor(std::move(pump));
  }

  quic::QuicEventLoop* event_loop_;
  quic::SocketFd listen_fd_;
  std::vector<ManagedSession>* sessions_;
  ClientOptions options_;
  size_t round_robin_ = 0;
};

int Main(int argc, char** argv) {
  // quiche defaults to only printing WARNING and above; without this, every
  // QUICHE_LOG(INFO) call in quictun (connection status, stream open/close,
  // the periodic RTT/bandwidth stats) is silently dropped. An explicit
  // --stderrthreshold=N on the command line still overrides this.
  absl::SetStderrThreshold(absl::LogSeverityAtLeast::kInfo);
  quiche::QuicheSystemEventLoop system_event_loop("quictun-client");
  const char* usage = "Usage: quictun_client --remote=host:port [options]";
  quiche::QuicheParseCommandLineFlags(usage, argc, argv);

  std::string remote = quiche::GetQuicheCommandLineFlag(FLAGS_remote);
  if (remote.empty()) {
    QUICHE_LOG(ERROR) << "--remote is required";
    return 1;
  }
  std::string key = quiche::GetQuicheCommandLineFlag(FLAGS_key);
  if (const char* env_key = std::getenv("QUICTUN_KEY");
      env_key != nullptr && env_key[0] != '\0') {
    key = env_key;
  }
  bool quiet = quiche::GetQuicheCommandLineFlag(FLAGS_quiet);
  int32_t conn = quiche::GetQuicheCommandLineFlag(FLAGS_conn);
  if (conn < 1) conn = 1;

  absl::StatusOr<quic::QuicSocketAddress> server_address =
      ResolveHostPort(remote);
  if (!server_address.ok()) {
    QUICHE_LOG(ERROR) << server_address.status();
    return 1;
  }
  std::string local = quiche::GetQuicheCommandLineFlag(FLAGS_local);
  absl::StatusOr<quic::QuicSocketAddress> local_address =
      ResolveHostPort(local);
  if (!local_address.ok()) {
    QUICHE_LOG(ERROR) << local_address.status();
    return 1;
  }

  ClientOptions options{
      *server_address,
      quic::QuicServerId("quictun.invalid",
                         static_cast<uint16_t>(server_address->port())),
      ComputeAuthToken(key), quiet};

  std::unique_ptr<quic::QuicEventLoop> event_loop =
      quic::GetDefaultEventLoop()->Create(quic::QuicDefaultClock::Get());

  QUICHE_LOG(INFO) << "quictun-client starting: remote=" << *server_address
                   << " conn=" << conn << " local=" << *local_address;

  std::vector<ManagedSession> sessions;
  sessions.reserve(conn);
  for (int32_t i = 0; i < conn; ++i) {
    sessions.push_back(DialUntilConnected(event_loop.get(), options));
  }

  absl::StatusOr<quic::SocketFd> listen_fd =
      CreateListeningSocket(*local_address);
  if (!listen_fd.ok()) {
    QUICHE_LOG(ERROR) << "failed to listen on " << *local_address << ": "
                      << listen_fd.status();
    return 1;
  }
  LocalListener listener(event_loop.get(), *listen_fd, &sessions, options);
  QUICHE_LOG(INFO) << "listening on " << *local_address;

  while (true) {
    event_loop->RunEventLoopOnce(quic::QuicTimeDelta::FromMilliseconds(200));
  }
}

}  // namespace
}  // namespace quictun

int main(int argc, char** argv) { return quictun::Main(argc, argv); }
