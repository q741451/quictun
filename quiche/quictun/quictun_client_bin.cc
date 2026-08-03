// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// quictun-client: forwards a local TCP port to a quictun-server over QUIC,
// analogous to `kcptun -l <local> -r <remote>` but with QUIC (via
// google/quiche's WebTransport-over-HTTP/3) standing in for KCP+smux.

#include <algorithm>
#include <cstddef>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
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
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_default_clock.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_server_id.h"
#include "quiche/quic/core/quic_tag.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/fake_proof_verifier.h"
#include "quiche/quic/tools/quic_event_loop_tools.h"
#include "quiche/quic/tools/web_transport_only_client.h"
#include "quiche/quictun/quictun_auth.h"
#include "quiche/quictun/tcp_util.h"
#include "quiche/quictun/tunnel_id.h"
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
DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, autoexpire, 0,
    "Seconds a pooled QUIC connection is allowed to carry tunnels before "
    "being replaced outright, to dodge ISP QoS shaping that keeps punishing "
    "a flow even after a mere UDP-layer port/connection-ID change (QUIC "
    "connection migration). The timer for a given pooled connection only "
    "starts once it actually carries its first tunnel, not from when it "
    "was dialed -- an idle connection is never proactively replaced. On "
    "expiry, a replacement connection is dialed in the background and only "
    "swapped in once fully connected (so nothing stalls waiting on it); "
    "every tunnel currently on the expiring connection is then moved onto "
    "the replacement, and the old connection is discarded. Whatever tail of "
    "already-sent, not-yet-acknowledged bytes was still in flight on the "
    "old connection at that point is lost -- waiting for it to drain first "
    "would let a single degraded connection stall every tunnel on it. "
    "0 disables this entirely.");

namespace quictun {
namespace {

struct ClientOptions {
  quic::QuicSocketAddress server_address;
  quic::QuicServerId server_id;
  std::string auth_token;
  bool quiet;
  absl::Duration autoexpire;
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
  // absl::InfiniteFuture() means "never carried a tunnel yet"; autoexpire's
  // per-connection timer only starts once this is set to a real timestamp,
  // on first use (see LocalListener::HandleAccepted /
  // CheckSessionReplacements) -- an idle pooled connection is never
  // proactively replaced.
  absl::Time first_used = absl::InfiniteFuture();
};

// Starts a new QUIC/WebTransport session to the server without blocking for
// it to become ready: ConnectSync() only creates the CONNECT stream, so the
// returned ManagedSession's visitor is usually not ready() yet (and may
// never become so, e.g. a bad --key gets rejected) -- see ready()/closed()
// on the returned visitor. `visitor` is null only if ConnectSync() itself
// failed outright (could not even create the CONNECT stream).
ManagedSession StartDial(quic::QuicEventLoop* event_loop,
                         const ClientOptions& options) {
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
  if (!status.ok()) {
    if (!options.quiet) {
      QUICHE_LOG(INFO) << "re-connecting: " << status;
    }
    return ManagedSession{};
  }
  return ManagedSession{std::move(client), visitor_ptr};
}

// Blocks (retrying once a second) until a new QUIC/WebTransport session to
// the server is established. Mirrors kcptun client's waitConn(). Only used
// where blocking is actually acceptable: filling the pool at startup
// (before the local listener is even open) and the rare case of a pool
// slot whose session died between TCP accepts. Runtime autoexpire
// replacement uses StartDial() directly instead, precisely to avoid
// blocking the event loop -- see CheckSessionReplacements().
ManagedSession DialUntilConnected(quic::QuicEventLoop* event_loop,
                                  const ClientOptions& options) {
  while (true) {
    ManagedSession session = StartDial(event_loop, options);
    if (session.visitor != nullptr) {
      // ConnectSync() only confirms the CONNECT stream was created, not
      // that the server actually accepted the session (e.g. rejected a
      // bad --key with 403) -- that's only known once OnSessionReady() or
      // OnSessionClosed() fires, asynchronously. Wait for a definitive
      // answer here rather than handing back a session whose readiness
      // callers can't yet trust; see the comment at the ready() check in
      // LocalListener::HandleAccepted for what went wrong before this.
      bool settled = quic::ProcessEventsUntil(event_loop, [&] {
        return session.visitor->ready() || session.visitor->closed();
      });
      if (settled && session.visitor->ready()) {
        if (!options.quiet) {
          QUICHE_LOG(INFO) << "connected to " << options.server_address;
        }
        return session;
      }
      if (!options.quiet) {
        QUICHE_LOG(INFO) << (settled ? "session rejected by server"
                                     : "timed out waiting for session");
      }
    }
    absl::SleepFor(absl::Seconds(1));
  }
}

// Accepts local TCP connections and round-robins them across the pool of
// QUIC sessions, opening one new outgoing WebTransport stream per
// connection. Mirrors kcptun client's per-connection accept loop. Also owns
// the TunnelRegistry and drives autoexpire's connection-replacement cycle.
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

  // Called from Main()'s event loop roughly every 200ms, from a point that
  // is provably not nested inside any TunnelPump/StreamAdapter callback --
  // see the class comment on TunnelPump for why SweepClosed() requires
  // that, and CheckSessionReplacements() for why the connection-teardown
  // half of autoexpire does too.
  void Tick() {
    registry_.SweepClosed();
    CheckSessionReplacements();
    SweepDrained();
  }

 private:
  void HandleAccepted(quic::SocketFd fd) {
    size_t idx = round_robin_ % sessions_->size();
    round_robin_++;
    ManagedSession& mux = (*sessions_)[idx];
    if (mux.visitor->closed()) {
      mux = DialUntilConnected(event_loop_, options_);
    }
    if (!mux.visitor->ready()) {
      // ConnectSync() only confirms the CONNECT stream was created, not
      // that the server actually accepted the session (e.g. a bad --key
      // gets a 403) -- that only happens asynchronously; closed() is what
      // tracks a *fully established* session tearing down. In between,
      // the underlying WebTransport session object is not guaranteed to
      // still be alive: a rejection can tear it down via the CONNECT
      // stream closing before OnSessionClosed() ever fires, at which
      // point mux.visitor->session() is a dangling pointer that closed()
      // hasn't caught up to yet. Touching it here was a real
      // use-after-free (crash reported against a wrong --key). Just
      // refuse the connection instead; the caller retries.
      if (!options_.quiet) {
        QUICHE_LOG(INFO) << "session not ready yet, dropping connection";
      }
      quic::socket_api::Close(fd);
      return;
    }
    webtransport::Session* session = mux.visitor->session();
    if (!session->CanOpenNextOutgoingBidirectionalStream()) {
      if (!options_.quiet) {
        QUICHE_LOG(INFO) << "stream flow control exhausted, dropping connection";
      }
      quic::socket_api::Close(fd);
      return;
    }
    if (!options_.quiet) {
      QUICHE_LOG(INFO) << "stream opened";
    }
    TunnelId id = GenerateTunnelId();
    webtransport::Stream* stream = session->OpenOutgoingBidirectionalStream();
    auto pump = std::make_unique<TunnelPump>(event_loop_, fd, options_.quiet,
                                             /*connecting=*/false, id);
    TunnelPump* pump_ptr = registry_.Register(id, std::move(pump));
    if (options_.autoexpire > absl::ZeroDuration()) {
      tunnel_session_idx_[id] = idx;
      if (mux.first_used == absl::InfiniteFuture()) {
        // First real use of this pooled connection -- start its
        // replacement timer now, not from when it was dialed, so an idle
        // pooled connection never gets torn down for no reason.
        mux.first_used = absl::Now();
      }
    }
    pump_ptr->AttachStream(stream, /*client_side=*/true);
  }

  // Drives autoexpire's two halves: (1) promote any background replacement
  // dial that has finished connecting, moving every tunnel still on the
  // connection it's replacing onto it and then discarding that old
  // connection; (2) start a new background replacement dial for any pooled
  // connection that's now overdue and isn't already being replaced. Never
  // blocks: a slow or stalled replacement dial simply leaves the expiring
  // connection in place (still serving its tunnels normally) until it's
  // ready, so nothing about existing traffic stalls while it happens --
  // this is what fixes the old "speed drops to 0 for several seconds while
  // switching" symptom, which came from blocking the whole event loop on a
  // synchronous redial.
  void CheckSessionReplacements() {
    if (options_.autoexpire <= absl::ZeroDuration()) {
      return;
    }
    absl::Time now = absl::Now();

    for (auto it = pending_replacement_.begin();
        it != pending_replacement_.end();) {
      size_t idx = it->first;
      ManagedSession& staged = it->second;
      if (staged.visitor == nullptr || staged.visitor->closed()) {
        // The background dial failed outright or was rejected; restart it
        // rather than leaving this slot stuck retrying forever.
        staged = StartDial(event_loop_, options_);
        ++it;
        continue;
      }
      if (!staged.visitor->ready()) {
        ++it;  // Still connecting; check again next tick.
        continue;
      }
      // Ready: move every tunnel still on `idx` onto the replacement. A
      // tunnel already gone (finished, or reset) by now is simply skipped;
      // TunnelRegistry::SweepClosed() (called just before this, in Tick())
      // has already cleaned up the registry side of that.
      for (auto tit = tunnel_session_idx_.begin();
          tit != tunnel_session_idx_.end();) {
        if (tit->second != idx) {
          ++tit;
          continue;
        }
        TunnelPump* pump = registry_.Find(tit->first);
        if (pump == nullptr) {
          // absl::flat_hash_map::erase(iterator) returns void (unlike
          // std::unordered_map), hence post-increment-then-erase.
          tunnel_session_idx_.erase(tit++);
          continue;
        }
        if (staged.visitor->session()->CanOpenNextOutgoingBidirectionalStream()) {
          webtransport::Stream* new_stream =
              staged.visitor->session()->OpenOutgoingBidirectionalStream();
          pump->AttachStream(new_stream, /*client_side=*/true);
        }
        // Note: `tit->second` stays `idx` on purpose -- `staged` is about
        // to become sessions_[idx] in place below, so the pool index this
        // tunnel is recorded against does not change, only what that slot
        // contains.
        ++tit;
      }
      staged.first_used = now;  // Already in active use by whatever moved.
      if (!options_.quiet) {
        QUICHE_LOG(INFO) << "replaced pooled connection " << idx;
      }
      // Every tunnel's write side has already moved off the old connection
      // above, but Writev() can have buffered a substantial amount of data
      // into it that QUIC hasn't actually gotten onto the wire (and
      // acknowledged) yet -- bounded by the 6MB per-stream flow-control
      // window in BuildTunedQuicConfig(), not by anything accounted for
      // here. Destroying it immediately would silently drop all of that.
      // Instead let it keep running in the background, still fully
      // serviced by the event loop, so it gets a real chance to flush --
      // see SweepDrained() for when it actually gets torn down.
      ManagedSession retiring = std::move((*sessions_)[idx]);
      (*sessions_)[idx] = std::move(staged);
      draining_.push_back(
          {now + DrainGracePeriod(), std::move(retiring)});
      // absl::flat_hash_map::erase(iterator) returns void (unlike
      // std::unordered_map), hence post-increment-then-erase.
      pending_replacement_.erase(it++);
    }

    for (size_t idx = 0; idx < sessions_->size(); ++idx) {
      if (pending_replacement_.contains(idx)) {
        continue;
      }
      ManagedSession& mux = (*sessions_)[idx];
      if (mux.first_used == absl::InfiniteFuture()) {
        continue;  // Never used; not eligible for replacement.
      }
      if (now - mux.first_used < options_.autoexpire) {
        continue;  // Not due yet.
      }
      bool has_active_tunnel = false;
      for (const auto& [unused_id, session_idx] : tunnel_session_idx_) {
        if (session_idx == idx) {
          has_active_tunnel = true;
          break;
        }
      }
      if (!has_active_tunnel) {
        // Gone idle since it was last used -- don't burn a connection
        // replacement (and a fresh handshake with the server) on a
        // connection nothing is actually using; rearm its timer so it
        // gets a full fresh autoexpire lifetime the next time some tunnel
        // actually lands on it, matching "an unused connection is never
        // proactively timed out."
        mux.first_used = absl::InfiniteFuture();
        continue;
      }
      pending_replacement_[idx] = StartDial(event_loop_, options_);
    }
  }

  // A retiring connection gets this long, after being superseded, to
  // finish flushing whatever it already had buffered before being
  // destroyed outright. Capped at autoexpire itself so a very aggressive
  // autoexpire setting can't accumulate an unbounded number of connections
  // simultaneously draining in the background (each still holds a live
  // UDP socket and gets serviced by the event loop) -- worst case, roughly
  // one extra connection per pool slot at a time.
  absl::Duration DrainGracePeriod() const {
    constexpr absl::Duration kMaxDrainGracePeriod = absl::Seconds(10);
    return std::min(kMaxDrainGracePeriod, options_.autoexpire);
  }

  // Actually destroys retired connections once their drain grace period
  // has elapsed (or sooner, if the connection has already died on its own
  // -- nothing left to wait for). Called once per Tick(), from the same
  // safe top-level point as everything else here.
  //
  // Explicitly closing the connection here (rather than just letting the
  // ManagedSession's destructor silently drop it) matters: destroying a
  // QuicConnection object does NOT send it a CONNECTION_CLOSE (see
  // QuicConnection::~QuicConnection() -- it only cleans up local state).
  // Without an explicit close, the server has no way to learn this
  // connection is gone until its own idle-timeout fires, tens of seconds
  // later -- and until then, any of its streams still sitting in a
  // TunnelPump's read_queue_ (waiting for the FIN AttachStream() already
  // sent, in case it never actually arrived) block every tunnel entry
  // queued behind them for that entire window. An explicit close notifies
  // the server immediately instead.
  void SweepDrained() {
    absl::Time now = absl::Now();
    for (auto it = draining_.begin(); it != draining_.end();) {
      const absl::Time& deadline = it->first;
      ManagedSession& retiring = it->second;
      if (now >= deadline || retiring.visitor->closed()) {
        if (!retiring.visitor->closed()) {
          retiring.client->session()->connection()->CloseConnection(
              quic::QUIC_NO_ERROR, "autoexpire: connection retired",
              quic::ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
        }
        it = draining_.erase(it);
      } else {
        ++it;
      }
    }
  }

  quic::QuicEventLoop* event_loop_;
  quic::SocketFd listen_fd_;
  std::vector<ManagedSession>* sessions_;
  ClientOptions options_;
  size_t round_robin_ = 0;

  TunnelRegistry registry_;
  // Which pool index a given tunnel's stream currently lives on; only
  // populated when autoexpire is enabled.
  absl::flat_hash_map<TunnelId, size_t> tunnel_session_idx_;
  // Pool index -> a replacement connection dialing in the background,
  // while sessions_[idx] keeps serving whatever tunnels are still on it
  // undisturbed. At most one replacement in flight per index at a time.
  absl::flat_hash_map<size_t, ManagedSession> pending_replacement_;
  // Superseded connections given a bounded grace period (DrainGracePeriod())
  // to flush already-buffered data before being destroyed -- see the
  // comment where this is populated, in CheckSessionReplacements().
  std::vector<std::pair<absl::Time, ManagedSession>> draining_;
};

int Main(int argc, char** argv) {
  // quic::socket_api::Send() (tunnel_pump.cc's FlushPendingToSocket) is a
  // bare ::send() with no MSG_NOSIGNAL, so writing to a local TCP socket
  // whose peer already reset the connection -- routine under heavy
  // concurrent traffic, where browsers cancel/close proxied downloads
  // constantly -- delivers SIGPIPE. Left at its default disposition, that
  // kills the whole process instantly with no log line and no crash
  // report, which is exactly what an EPIPE from Send() should have become
  // instead (CloseAll() on that one connection).
  signal(SIGPIPE, SIG_IGN);
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
  int32_t autoexpire_secs = quiche::GetQuicheCommandLineFlag(FLAGS_autoexpire);
  absl::Duration autoexpire = autoexpire_secs > 0
                                  ? absl::Seconds(autoexpire_secs)
                                  : absl::ZeroDuration();

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
      ComputeAuthToken(key), quiet, autoexpire};

  std::unique_ptr<quic::QuicEventLoop> event_loop =
      quic::GetDefaultEventLoop()->Create(quic::QuicDefaultClock::Get());

  QUICHE_LOG(INFO) << "quictun-client starting: remote=" << *server_address
                   << " conn=" << conn << " local=" << *local_address
                   << " autoexpire=" << autoexpire;

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
    listener.Tick();
  }
}

}  // namespace
}  // namespace quictun

int main(int argc, char** argv) { return quictun::Main(argc, argv); }
