// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_client_driver.h"

#include <algorithm>
#include <iostream>
#include <memory>
#include <optional>
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
  // See --max_streams_per_connection's own comment (quictun_flags.h) --
  // set here for symmetry/consistency with the server side, but in
  // practice never has anything to bite: quictun's streams are always
  // client-initiated, so the server never opens a stream to the client
  // for this (the client's own incoming limit) to ever gate.
  config_template_.SetMaxBidirectionalStreamsToSend(
      options.max_streams_per_connection);

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

  // Nothing stops a zero or negative --udp_socket/--conn_per_udp being
  // passed on the command line; both are obviously typos, and one of each
  // is the smallest thing that still works.
  udp_socket_count_ = static_cast<size_t>(std::max(options.udp_socket, 1));
  pool_slots_.resize(udp_socket_count_ *
                     static_cast<size_t>(std::max(options.conn_per_udp, 1)));
}

absl::Status QuictunClientDriver::Start() {
  // One socket per --udp_socket, each on its own ephemeral source port
  // (bind is implicit in connect()) -- see --udp_socket's own comment.
  for (size_t i = 0; i < udp_socket_count_; ++i) {
    auto entry = std::make_unique<UdpSocket>();
    absl::StatusOr<OwnedSocketFd> ufd =
        CreateQuicUdpSocket(remote_address_, options_.udp_socket_buffer_bytes);
    if (!ufd.ok()) {
      return ufd.status();
    }
    entry->fd = *std::move(ufd);
    absl::Status cs = socket_api::Connect(*entry->fd, remote_address_);
    if (!cs.ok()) {
      return cs;
    }
    absl::StatusOr<QuicSocketAddress> self =
        socket_api::GetSocketAddress(*entry->fd);
    if (!self.ok()) {
      return self.status();
    }
    entry->self_address = *self;
    entry->writer =
        MakeQuictunPacketWriter(*entry->fd, options_.so_txtime, event_loop_);
    if (!event_loop_->RegisterSocket(
            *entry->fd,
            kSocketEventReadable | kSocketEventWritable | kSocketEventError,
            this)) {
      return absl::InternalError("failed to register a UDP socket");
    }
    udp_sockets_.push_back(std::move(entry));
  }

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

QuictunClientDriver::UdpSocket* QuictunClientDriver::FindUdpSocketByFd(
    SocketFd fd) {
  for (const std::unique_ptr<UdpSocket>& entry : udp_sockets_) {
    if (*entry->fd == fd) {
      return entry.get();
    }
  }
  return nullptr;
}

void QuictunClientDriver::OnSocketEvent(QuicEventLoop* /*event_loop*/,
                                        SocketFd fd,
                                        QuicSocketEventMask events) {
  if (UdpSocket* udp = FindUdpSocketByFd(fd); udp != nullptr) {
    if (events & kSocketEventError) {
      // Consume it so a level-triggered loop does not spin on an unread
      // POLLERR; deliberately not acted on (trivially spoofable, and on a
      // socket shared by several connections not attributable to any one
      // of them).
      absl::Status error = socket_api::GetSocketError(*udp->fd);
      if (!error.ok()) {
        QUIC_LOG_EVERY_N_SEC(INFO, 10)
            << "quictun UDP socket reported an error (consumed): " << error;
      }
      if (!event_loop_->SupportsEdgeTriggered()) {
        event_loop_->RearmSocket(*udp->fd, kSocketEventError);
      }
    }
    if (events & kSocketEventWritable) {
      // Mirrors QuicDispatcher::OnCanWrite().
      udp->writer->SetWritable();
      udp->write_blocked_list.OnWriterUnblocked();
      if (!udp->write_blocked_list.Empty() &&
          !event_loop_->SupportsEdgeTriggered()) {
        event_loop_->RearmSocket(*udp->fd, kSocketEventWritable);
      }
    }
    if (events & kSocketEventReadable) {
      bool more = true;
      while (more) {
        more = udp_reader_.ReadAndDispatchPackets(
            *udp->fd, udp->self_address.port(), *event_loop_->GetClock(), this,
            nullptr);
      }
      if (!event_loop_->SupportsEdgeTriggered()) {
        event_loop_->RearmSocket(*udp->fd, kSocketEventReadable);
      }
    }
    return;
  }
  if (events & kSocketEventReadable) {
    AcceptLoop();
    if (!event_loop_->SupportsEdgeTriggered()) {
      event_loop_->RearmSocket(*listen_fd_, kSocketEventReadable);
    }
  }
}

std::shared_ptr<QuictunClientConnection>
QuictunClientDriver::CreateNewConnection(size_t socket_index) {
  UdpSocket& udp = *udp_sockets_[socket_index];
  // Unique per connection and never reused: it is the routing key for every
  // packet the server sends back, on whichever socket (see ProcessPacket()).
  const uint64_t raw_cid = next_client_cid_++;
  QuicConnectionId cid(reinterpret_cast<const char*>(&raw_cid),
                       sizeof(raw_cid));
  std::unique_ptr<QuictunClientConnection> connection =
      QuictunClientConnection::Create(
          event_loop_, &helper_, alarm_factory_.get(),
          connection_id_generator_, buffer_allocator_, config_template_,
          server_id_, remote_address_, crypto_config_.get(), options_.psk,
          congestion_control_, options_.so_txtime,
          options_.transparent, udp.writer.get(), cid,
          &idle_tracker_,
          [this, socket_index](QuicBlockedWriterInterface* w) {
            OnWriteBlocked(w, socket_index);
          },
          [this, socket_index](QuictunClientConnection* c) {
            RemoveConnection(c, socket_index);
          });
  if (connection == nullptr) {
    return nullptr;
  }
  by_cid_.emplace(cid, connection.get());
  SetQuictunStartupBandwidthHint(connection->connection(),
                                 options_.startup_bandwidth_kbps,
                                 options_.startup_rtt_ms);
  std::shared_ptr<QuictunClientConnection> shared(std::move(connection));
  connections_.emplace(shared.get(), shared);
  return shared;
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

    // --transparent: capture the destination an external iptables/nftables
    // REDIRECT rule sent this connection's way, before it was redirected to
    // --local -- see CaptureQuictunOriginalDestination()'s own comment.
    // Required whenever --transparent is set: unlike --target mode, there
    // is no fixed fallback destination to tunnel this connection to if
    // capture fails (e.g. it was connected to --local directly, without
    // ever going through a REDIRECT rule at all) -- refuse it outright
    // rather than silently dropping it into some other stream's real
    // destination or sending a malformed header the server would have to
    // guess about.
    std::optional<QuicSocketAddress> captured_dest;
    if (options_.transparent) {
      captured_dest = CaptureQuictunOriginalDestination(accepted->fd);
      if (!captured_dest.has_value()) {
        socket_api::Close(accepted->fd);
        continue;
      }
    }

    // Round-robin over the flat pool, lazily creating or replacing the
    // slot it lands on -- see pool_slots_'s comment for the algorithm and
    // for how slots map onto sockets. A connection that's still
    // mid-handshake is neither nullptr nor closed(), so it's treated as
    // available here exactly like a fully-established one: AssignNewTcp()
    // queues the new TCP if OpenOutgoingStream() isn't possible yet, same
    // as it always does.
    const size_t idx = pool_round_robin_next_ % pool_slots_.size();
    pool_round_robin_next_++;
    std::shared_ptr<QuictunClientConnection> conn = pool_slots_[idx].lock();
    if (conn == nullptr || conn->closed()) {
      conn = CreateNewConnection(idx % udp_socket_count_);
      if (conn == nullptr) {
        socket_api::Close(accepted->fd);
        continue;
      }
      pool_slots_[idx] = conn;
    }
    conn->AssignNewTcp(accepted->fd, accepted->peer_address, captured_dest);
  }
}

void QuictunClientDriver::RemoveConnection(QuictunClientConnection* connection,
                                          size_t socket_index) {
  // Mirrors QuicDispatcher::OnConnectionClosed(): the blocked-writer list
  // holds a raw QuicBlockedWriterInterface*, and QuicConnection's own
  // destructor does not unregister itself, so a connection still listed
  // when CollectGarbage() destroys it would leave a dangling entry for the
  // next writable event to call OnBlockedWriterCanWrite() on.
  udp_sockets_[socket_index]->write_blocked_list.Remove(
      *connection->connection());
  // Drop the routing entry immediately: from here on any straggler packet
  // for it (a late retransmission, the peer still writing) must be dropped
  // rather than delivered to a connection queued for destruction.
  absl::erase_if(by_cid_, [connection](const auto& e) {
    return e.second == connection;
  });
  pending_removal_.push_back(connection);
}

void QuictunClientDriver::OnWriteBlocked(
    QuicBlockedWriterInterface* blocked_writer, size_t socket_index) {
  UdpSocket& udp = *udp_sockets_[socket_index];
  udp.write_blocked_list.Add(*blocked_writer);
  if (!event_loop_->SupportsEdgeTriggered()) {
    event_loop_->RearmSocket(*udp.fd, kSocketEventWritable);
  }
}

void QuictunClientDriver::ProcessPacket(const QuicSocketAddress& self_address,
                                        const QuicSocketAddress& peer_address,
                                        const QuicReceivedPacket& packet) {
  PacketHeaderFormat format;
  QuicLongHeaderType long_packet_type;
  bool version_present;
  bool has_length_prefix;
  QuicVersionLabel version_label;
  ParsedQuicVersion parsed_version = ParsedQuicVersion::Unsupported();
  absl::string_view destination_connection_id;
  absl::string_view source_connection_id;
  std::optional<absl::string_view> retry_token;
  std::string detailed_error;
  if (QuicFramer::ParsePublicHeaderDispatcherShortHeaderLengthUnknown(
          packet, &format, &long_packet_type, &version_present,
          &has_length_prefix, &version_label, &parsed_version,
          &destination_connection_id, &source_connection_id, &retry_token,
          &detailed_error, connection_id_generator_) != QUIC_NO_ERROR) {
    QUIC_DVLOG(1) << "Dropping unparseable packet from " << peer_address << ": "
                  << detailed_error;
    return;
  }
  auto it = by_cid_.find(QuicConnectionId(destination_connection_id));
  if (it == by_cid_.end()) {
    QUIC_DVLOG(1) << "Dropping packet for unknown connection ID "
                  << QuicConnectionId(destination_connection_id);
    return;
  }
  it->second->ProcessPacket(self_address, peer_address, packet);
}

void QuictunClientDriver::CollectGarbage() {
  // Per-stream cleanup no longer needs anything from here: each
  // QuictunClientConnection now drives its own stream_garbage_alarm_ (see
  // its class comment), mirroring how real QUICHE's QuicSession cleans up
  // closed_streams_ via its own alarm rather than something external
  // polling it. This method only ever handled whole-connection removal.
  for (QuictunClientConnection* connection : pending_removal_) {
    // Look it up rather than dereferencing straight away, so this stays
    // correct on its own terms if the same connection is ever queued twice
    // -- matching QuictunServerDriver::CollectGarbage().
    auto it = connections_.find(connection);
    if (it == connections_.end()) {
      continue;
    }
    // Same backstop as the server's. Scans every socket rather than the one
    // the connection was created on: the point is to catch a connection
    // that got back onto some list after RemoveConnection() already ran, so
    // trusting that index would defeat it. --udp_socket is a handful of
    // entries at most.
    for (const std::unique_ptr<UdpSocket>& udp : udp_sockets_) {
      if (udp->write_blocked_list.Remove(*connection->connection())) {
        QUIC_BUG(quictun_bug_client_blocked_writer_at_destruction)
            << "Connection was still in the blocked-writer list at destruction";
      }
    }
    connections_.erase(it);
  }
  pending_removal_.clear();
}

void QuictunClientDriver::CloseIdleTunnels() {
  idle_tracker_.CloseIdleTunnels(
      event_loop_->GetClock()->ApproximateNow(), options_.tcp_idle_timeout,
      // A stalled tunnel outliving a merely quiet one is never what an
      // operator meant, so a --tcp_stalled_timeout_seconds above
      // --tcp_idle_timeout_seconds is read as "no separate stalled class".
      std::min(options_.tcp_stalled_timeout, options_.tcp_idle_timeout));
}

}  // namespace quic
