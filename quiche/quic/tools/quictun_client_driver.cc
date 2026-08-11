// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_client_driver.h"

#include <iostream>
#include <memory>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/tools/quictun_connection_factory.h"
#include "quiche/quic/tools/fake_proof_verifier.h"
#include "quiche/quic/tools/quictun_reusable_session_cache.h"
#include "quiche/quic/tools/quictun_socket_util.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/simple_buffer_allocator.h"

namespace quic {

QuictunClientDriver::QuictunClientDriver(QuicEventLoop* event_loop,
                                         const QuicSocketAddress& local_address,
                                         const QuicSocketAddress& remote_address,
                                         const QuictunTuningOptions& options)
    : event_loop_(event_loop),
      local_address_(local_address),
      remote_address_(remote_address),
      options_(options),
      alarm_factory_(event_loop_->CreateAlarmFactory()),
      connection_id_generator_(kQuicDefaultConnectionIdLength),
      server_id_(remote_address.host().ToString(), remote_address.port()),
      buffer_allocator_(quiche::SimpleBufferAllocator::Get()),
      congestion_control_(
          ParseQuictunCongestionControl(options.congestion_control)) {
  config_template_.SetIdleNetworkTimeout(options.idle_timeout);
  config_template_.SetInitialStreamFlowControlWindowToSend(
      options.initial_stream_flow_control_window_bytes);
  config_template_.SetInitialSessionFlowControlWindowToSend(
      options.initial_session_flow_control_window_bytes);

  // NOTE: QuicCryptoClientConfig::set_pre_shared_key() is *not* used here --
  // it's an unimplemented stub for TLS-based QUIC in this snapshot
  // (TlsClientHandshaker::CryptoConnect() hard-crashes via QUIC_BUG if a PSK
  // is configured; see tls_client_handshaker.cc's
  // "QUIC client pre-shared keys not yet supported with TLS"). --key is
  // instead checked as an application-layer preamble on the tunnel's
  // stream -- see QuictunClientConnection's constructor and
  // QuictunServerConnection::OnStreamDataAvailable().
  // QuictunReusableSessionCache, not the stock QuicClientSessionCache: lets
  // a burst of concurrent connections to the same --remote all use 0-RTT
  // off the same cached ticket instead of only the first 1-2 of them --
  // see that class's header comment for the (accepted, for quictun's own
  // deployment) replay-defense trade-off this makes.
  crypto_config_ = std::make_unique<QuicCryptoClientConfig>(
      std::make_unique<FakeProofVerifier>(),
      options.zero_rtt ? std::make_shared<QuictunReusableSessionCache>()
                        : nullptr);

  if (options.so_txtime) {
    EnableQuictunSoTxTime();
  }

  // See pool_slots_'s comment: only exists in pooling mode. A negative
  // --quic_conn (nothing stops one being passed on the command line) just
  // takes this same branch as 0 -- harmless, not worth a separate
  // validation error for what's obviously a typo anyway.
  if (options.quic_conn > 0) {
    pool_slots_.resize(options.quic_conn, nullptr);
  }
}

absl::Status QuictunClientDriver::Start() {
  absl::StatusOr<SocketFd> fd = socket_api::CreateSocket(
      local_address_.host().address_family(), socket_api::SocketProtocol::kTcp,
      /*blocking=*/false);
  if (!fd.ok()) {
    return fd.status();
  }
  listen_fd_ = OwnedSocketFd(*fd);

  // Without SO_REUSEADDR, restarting quictun_client shortly after it served
  // any connections fails to rebind --local: those connections' local
  // 4-tuples (sharing this listen port) linger in TIME_WAIT for up to a
  // couple of minutes, and the kernel refuses a fresh bind() to the same
  // port for a plain listening socket during that window.
  absl::Status status = SetReuseAddrAndPort(*listen_fd_);
  if (!status.ok()) {
    return status;
  }

  if (local_address_.host().address_family() == IpAddressFamily::IP_V6) {
    status = SetIpv6OnlyDisabled(*listen_fd_);
    if (!status.ok()) {
      return status;
    }
  }

  status = socket_api::Bind(*listen_fd_, local_address_);
  if (!status.ok()) {
    return status;
  }
  status = socket_api::Listen(*listen_fd_, /*backlog=*/64);
  if (!status.ok()) {
    return status;
  }

  bool registered = event_loop_->RegisterSocket(
      *listen_fd_, kSocketEventReadable, this);
  if (!registered) {
    return absl::InternalError("Failed to register TCP listen socket");
  }

  // std::cerr, not QUIC_LOG(INFO): see the comment on
  // PrintQuictunStartupBanner() in quictun_flags.cc -- this is the "bind
  // actually succeeded, tunnel is ready" confirmation that completes the
  // startup banner, and needs the same default visibility.
  std::cerr << "quictun_client listening on " << local_address_
            << ", tunneling to " << remote_address_ << std::endl;
  return absl::OkStatus();
}

void QuictunClientDriver::OnSocketEvent(QuicEventLoop* /*event_loop*/,
                                        SocketFd /*fd*/,
                                        QuicSocketEventMask events) {
  if (events & kSocketEventReadable) {
    AcceptLoop();
    if (!event_loop_->SupportsEdgeTriggered()) {
      event_loop_->RearmSocket(*listen_fd_, kSocketEventReadable);
    }
  }
}

QuictunClientConnection* QuictunClientDriver::CreateNewConnection() {
  std::unique_ptr<QuictunClientConnection> connection =
      QuictunClientConnection::Create(
          event_loop_, &helper_, alarm_factory_.get(),
          connection_id_generator_, buffer_allocator_, config_template_,
          server_id_, remote_address_, crypto_config_.get(), options_.psk,
          congestion_control_, options_.so_txtime,
          options_.udp_socket_buffer_bytes,
          [this](QuictunClientConnection* c) { RemoveConnection(c); });
  if (connection == nullptr) {
    return nullptr;
  }
  SetQuictunStartupBandwidthHint(connection->connection(),
                                 options_.startup_bandwidth_kbps,
                                 options_.startup_rtt_ms);
  QuictunClientConnection* raw = connection.get();
  connections_.emplace(raw, std::move(connection));
  return raw;
}

void QuictunClientDriver::AcceptLoop() {
  while (true) {
    absl::StatusOr<socket_api::AcceptResult> accepted =
        socket_api::Accept(*listen_fd_, /*blocking=*/false);
    if (!accepted.ok()) {
      if (!absl::IsUnavailable(accepted.status())) {
        QUIC_LOG(WARNING) << "Accept() failed: " << accepted.status();
      }
      return;
    }

    if (options_.quic_conn == 0) {
      // Unlimited: quictun's original behavior, completely unchanged --
      // every accepted TCP connection gets its own brand-new QUIC
      // connection. See pool_slots_'s comment for why this can't just be
      // "the pooling path below with a size-0 pool_slots_".
      QuictunClientConnection* connection = CreateNewConnection();
      if (connection == nullptr) {
        socket_api::Close(accepted->fd);
        continue;
      }
      connection->AssignNewTcp(accepted->fd, accepted->peer_address);
      continue;
    }

    // Pooling: kcptun's own --conn algorithm (see pool_slots_'s comment) --
    // round-robin over a fixed number of slots, lazily creating/replacing
    // whichever slot round-robin selects only when it's actually that
    // slot's turn to be used, rather than eagerly tracking liveness
    // separately. A connection that's still mid-handshake is neither
    // nullptr nor closed(), so it's treated as available here exactly like
    // a fully-established one -- AssignNewTcp() below queues the new TCP
    // if OpenOutgoingStream() isn't possible yet, same as it always does.
    size_t idx = pool_round_robin_next_ % pool_slots_.size();
    pool_round_robin_next_++;
    QuictunClientConnection*& slot = pool_slots_[idx];
    if (slot == nullptr || slot->closed()) {
      slot = CreateNewConnection();
      if (slot == nullptr) {
        socket_api::Close(accepted->fd);
        continue;
      }
    }
    slot->AssignNewTcp(accepted->fd, accepted->peer_address);
  }
}

void QuictunClientDriver::RemoveConnection(QuictunClientConnection* connection) {
  pending_removal_.push_back(connection);
}

void QuictunClientDriver::CollectGarbage() {
  // Per-stream cleanup first -- see QuictunServerDriver::CollectGarbage()'s
  // identical comment for why this needs to run for every still-live
  // connection here, not just the ones about to be erased below.
  for (const auto& kv : connections_) {
    kv.first->CollectStreamGarbage();
  }
  for (QuictunClientConnection* connection : pending_removal_) {
    connections_.erase(connection);
  }
  pending_removal_.clear();
}

}  // namespace quic
