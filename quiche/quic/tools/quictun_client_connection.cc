// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_client_connection.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_packet_writer.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/tools/quictun_connection_factory.h"
#include "quiche/quic/tools/quictun_session.h"
#include "quiche/quic/tools/quictun_socket_util.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace quic {

std::unique_ptr<QuictunClientConnection> QuictunClientConnection::Create(
    QuicEventLoop* event_loop, QuicConnectionHelperInterface* helper,
    QuicAlarmFactory* alarm_factory,
    ConnectionIdGeneratorInterface& connection_id_generator,
    quiche::QuicheBufferAllocator* buffer_allocator, const QuicConfig& config,
    const QuicServerId& server_id, const QuicSocketAddress& remote_address,
    QuicCryptoClientConfig* crypto_config, const std::string& psk,
    CongestionControlType congestion_control, bool so_txtime_enabled,
    QuicByteCount udp_socket_buffer_bytes,
    std::function<void(QuictunClientConnection*)> on_closed) {
  absl::StatusOr<OwnedSocketFd> fd =
      CreateQuicUdpSocket(remote_address, udp_socket_buffer_bytes);
  if (!fd.ok()) {
    QUIC_LOG(ERROR) << "Failed to create UDP socket for tunnel to "
                    << remote_address << ": " << fd.status();
    return nullptr;
  }
  OwnedSocketFd udp_fd = *std::move(fd);

  absl::Status connect_status = socket_api::Connect(*udp_fd, remote_address);
  if (!connect_status.ok()) {
    QUIC_LOG(ERROR) << "Failed to connect UDP socket to " << remote_address
                    << ": " << connect_status;
    return nullptr;
  }

  absl::StatusOr<QuicSocketAddress> self_address =
      socket_api::GetSocketAddress(*udp_fd);
  if (!self_address.ok()) {
    QUIC_LOG(ERROR) << "Failed to get local address for tunnel UDP socket: "
                    << self_address.status();
    return nullptr;
  }

  // Not using std::make_unique: constructor is private.
  return absl::WrapUnique(new QuictunClientConnection(
      event_loop, std::move(udp_fd), *self_address, remote_address, helper,
      alarm_factory, connection_id_generator, buffer_allocator, config,
      server_id, crypto_config, psk, congestion_control, so_txtime_enabled,
      std::move(on_closed)));
}

QuictunClientConnection::QuictunClientConnection(
    QuicEventLoop* event_loop, OwnedSocketFd udp_fd,
    const QuicSocketAddress& self_address,
    const QuicSocketAddress& remote_address, QuicConnectionHelperInterface* helper,
    QuicAlarmFactory* alarm_factory,
    ConnectionIdGeneratorInterface& connection_id_generator,
    quiche::QuicheBufferAllocator* buffer_allocator, const QuicConfig& config,
    const QuicServerId& server_id, QuicCryptoClientConfig* crypto_config,
    const std::string& psk, CongestionControlType congestion_control,
    bool so_txtime_enabled,
    std::function<void(QuictunClientConnection*)> on_closed)
    : event_loop_(event_loop),
      udp_fd_(std::move(udp_fd)),
      self_address_(self_address),
      psk_(psk),
      buffer_allocator_(buffer_allocator),
      idle_timeout_(config.IdleNetworkTimeout()),
      on_closed_(std::move(on_closed)) {
  std::unique_ptr<QuicPacketWriter> writer =
      MakeQuictunPacketWriter(*udp_fd_, so_txtime_enabled, event_loop);

  connection_ = std::make_unique<QuicConnection>(
      QuicUtils::CreateRandomConnectionId(), QuicSocketAddress(),
      remote_address, helper, alarm_factory, writer.release(),
      /*owns_writer=*/true, Perspective::IS_CLIENT, GetQuictunVersions(),
      connection_id_generator);
  SetQuictunCongestionControl(connection_.get(), congestion_control);

  session_ = std::make_unique<QuictunClientSession>(
      connection_.get(), /*owner=*/this, config, "quictun/1", server_id,
      crypto_config);
  session_->SetCanOpenStreamCallback([this] { MaybeOpenStreams(); });
  session_->Initialize();

  bool registered = event_loop_->RegisterSocket(
      *udp_fd_, kSocketEventReadable | kSocketEventWritable, this);
  QUICHE_DCHECK(registered);

  session_->CryptoConnect();
}

void QuictunClientConnection::AssignNewTcp(
    SocketFd accepted_tcp_fd, const QuicSocketAddress& tcp_peer_address) {
  if (closed_) {
    socket_api::Close(accepted_tcp_fd);
    return;
  }
  pending_tcps_.push_back({accepted_tcp_fd, tcp_peer_address});
  // Try right away -- succeeds immediately when a cached 0-RTT session (or,
  // under pooling, this connection's own already-confirmed handshake) has
  // already supplied a max_streams value allowing it. Otherwise this is a
  // no-op and MaybeOpenStreams() gets retried from
  // SetCanOpenStreamCallback() once QuicSession actually applies one (from
  // the negotiated transport parameters, for a fresh non-0-RTT connection,
  // or a later MAX_STREAMS frame).
  MaybeOpenStreams();
}

void QuictunClientConnection::MaybeOpenStreams() {
  while (!closed_ && !pending_tcps_.empty()) {
    QuictunStream* stream = session_->OpenOutgoingStream();
    if (stream == nullptr) {
      return;
    }
    PendingTcp pending = pending_tcps_.front();
    pending_tcps_.pop_front();
    StartTunnel(stream, pending);
  }
}

void QuictunClientConnection::StartTunnel(QuictunStream* stream,
                                          PendingTcp pending) {
  // quictun's own authentication: --key, sent as a length-prefixed preamble
  // (2-byte big-endian length + key bytes) that must always be the very
  // first bytes on the stream. This exists because
  // QuicCryptoClientConfig::set_pre_shared_key() -- the "real" TLS 1.3
  // external-PSK mechanism -- turns out to be unimplemented for TLS-based
  // QUIC in this snapshot (TlsClientHandshaker::CryptoConnect() hard-crashes
  // via QUIC_BUG if it's set; see quictun_client_driver.cc's comment). This
  // is a strictly weaker authentication property than a real TLS-level PSK
  // (it doesn't bind the key into the handshake's key schedule, so it can't
  // by itself defeat an active on-path attacker who completes the TLS
  // handshake with the client -- the client never validates the server's
  // certificate at all, see FakeProofVerifier), but matches this tool's
  // explicitly low security bar: it rejects any connection that doesn't
  // know the shared secret. Sent fresh on every stream (not just this
  // connection's first), one per TCP tunnel -- see
  // QuictunServerConnection::OnStreamDataAvailable for the server-side
  // check, done the same way, once per stream.
  std::string preamble;
  preamble.push_back(static_cast<char>((psk_.size() >> 8) & 0xff));
  preamble.push_back(static_cast<char>(psk_.size() & 0xff));
  preamble.append(psk_);
  stream->WriteToStream(preamble, /*fin=*/false);

  QuicStreamId id = stream->id();
  StreamTcp& entry = stream_tcps_[id];
  // QuictunTunnel and QuictunAcceptedTcpSocket each need a pointer to the
  // other at construction (tunnel needs the socket to pump through; the
  // socket needs the tunnel as its AsyncVisitor) -- construct the socket
  // with no visitor yet, then wire it up once the tunnel exists.
  entry.tcp_socket = std::make_unique<QuictunAcceptedTcpSocket>(
      pending.fd, pending.peer_address, event_loop_, buffer_allocator_,
      /*async_visitor=*/nullptr);
  entry.tunnel = std::make_unique<QuictunTunnel>(
      stream, entry.tcp_socket.get(), idle_timeout_, [this, id] {
        // This stream's tunnel closed itself -- scoped to just this one
        // TCP, same reasoning as the server-side mirror of this callback
        // (QuictunServerConnection::StartTunnelForStream()): other streams
        // sharing this connection (--quic_conn pooling) may still be
        // actively tunneling and shouldn't be torn down just because one
        // of them finished. QuictunTunnel::Close() always disconnects
        // tcp_socket_ itself when it has one (unlike the server's
        // dial-out, this one is always already connected by the time the
        // tunnel exists -- see the constructor -- so HasSocket() is always
        // true here; no need for QuictunServerConnection's extra check).
        //
        // Same use-after-free hazard as the server-side mirror (see
        // QuictunServerConnection::StartTunnelForStream()'s comment): this
        // callback runs from inside QuictunTunnel::Close(), a member
        // function of the very QuictunTunnel that entry.tunnel owns, which
        // keeps executing after this callback returns. Erasing here would
        // destroy that QuictunTunnel out from under its own still-running
        // Close(). Only mark-and-defer; CollectStreamGarbage() does the
        // actual erase() later, outside any tunnel's call stack.
        auto it = stream_tcps_.find(id);
        if (it == stream_tcps_.end()) {
          return;
        }
        it->second.tcp_socket_disconnected = true;
        pending_stream_removal_.push_back(id);
      });
  entry.tcp_socket->SetAsyncVisitor(entry.tunnel.get());
  session_->SetStreamDelegate(id, entry.tunnel.get());
  entry.tunnel->Start();
}

void QuictunClientConnection::CollectStreamGarbage() {
  // See QuictunServerConnection::CollectStreamGarbage()'s comment -- same
  // deferred-destruction pattern, one class over. Actually erase()s (and so
  // destroys the StreamTcp -- QuictunTunnel and tcp_socket included) now
  // safely outside any tunnel's own call stack.
  for (QuicStreamId id : pending_stream_removal_) {
    stream_tcps_.erase(id);
  }
  pending_stream_removal_.clear();
}

QuictunClientConnection::~QuictunClientConnection() {
  if (event_loop_->UnregisterSocket(*udp_fd_)) {
    // Expected: still registered unless Close() already ran.
  }
}

void QuictunClientConnection::Close() {
  if (closed_) {
    return;
  }
  closed_ = true;
  if (connection_->connected()) {
    connection_->CloseConnection(
        QUIC_NO_ERROR, "quictun tunnel closed",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  }
  // Every stream's TCP side: disconnect (see the identical reasoning in
  // QuictunServerConnection::Close() for why this doesn't go through each
  // tunnel's own Close() instead -- reentrant modification of stream_tcps_
  // while iterating it).
  for (auto& [id, entry] : stream_tcps_) {
    if (entry.tcp_socket && !entry.tcp_socket_disconnected) {
      entry.tcp_socket_disconnected = true;
      entry.tcp_socket->Disconnect();
    }
  }
  stream_tcps_.clear();
  // See QuictunServerConnection::Close()'s identical comment: entries
  // already gone via the clear() above, this just avoids leaving stale ids
  // sitting around in a connection that's about to be destroyed anyway.
  pending_stream_removal_.clear();
  // Any TCPs that never even got a stream opened for them yet: nothing
  // owns these but this queue, so close the raw fd directly.
  for (const PendingTcp& pending : pending_tcps_) {
    socket_api::Close(pending.fd);
  }
  pending_tcps_.clear();
  event_loop_->UnregisterSocket(*udp_fd_);
  std::function<void(QuictunClientConnection*)> on_closed =
      std::move(on_closed_);
  if (on_closed) {
    on_closed(this);
  }
}

void QuictunClientConnection::OnConnectionClosed(
    QuicConnectionId /*server_connection_id*/, QuicErrorCode error,
    const std::string& error_details, ConnectionCloseSource source) {
  // EarlyDataAccepted()/EarlyDataReason() are only meaningful (and only
  // safe to call -- TlsClientHandshaker::EarlyDataAccepted() itself
  // QUIC_BUG_IFs otherwise) once the handshake has actually produced 1-RTT
  // keys. A connection that never gets that far (e.g. ECONNREFUSED before
  // any handshake progress) hits this constantly, spamming an unrelated,
  // message-less quic_bug_12736_2 on every single closed attempt.
  if (session_->OneRttKeysAvailable()) {
    QUIC_LOG(INFO) << "quictun connection closed: "
                   << QuicErrorCodeToString(error) << " (\"" << error_details
                   << "\"), source="
                   << (source == ConnectionCloseSource::FROM_PEER ? "PEER"
                                                                   : "SELF")
                   << ", EarlyDataAccepted=" << session_->EarlyDataAccepted()
                   << " EarlyDataReason=" << session_->EarlyDataReason();
  } else {
    QUIC_LOG(INFO) << "quictun connection closed: "
                   << QuicErrorCodeToString(error) << " (\"" << error_details
                   << "\"), source="
                   << (source == ConnectionCloseSource::FROM_PEER ? "PEER"
                                                                   : "SELF")
                   << " (handshake never completed)";
  }
  Close();
}

void QuictunClientConnection::OnSocketEvent(QuicEventLoop* /*event_loop*/,
                                            SocketFd fd,
                                            QuicSocketEventMask events) {
  QUICHE_DCHECK_EQ(fd, *udp_fd_);
  if (events & kSocketEventReadable) {
    bool more_to_read = true;
    while (more_to_read) {
      more_to_read = reader_.ReadAndDispatchPackets(
          *udp_fd_, self_address_.port(), *event_loop_->GetClock(), this,
          /*packets_dropped=*/nullptr);
    }
    if (!event_loop_->SupportsEdgeTriggered()) {
      event_loop_->RearmSocket(*udp_fd_, kSocketEventReadable);
    }
  }
  if (events & kSocketEventWritable) {
    // OnBlockedWriterCanWrite(), not plain OnCanWrite(): this event means
    // "the OS says the socket is writable again", which is specifically
    // what clears the writer's own write_blocked_ bookkeeping first (see
    // QuicConnection::OnBlockedWriterCanWrite() and, for the reference
    // pattern this mirrors, QuicDispatcher::OnCanWrite() in
    // quic_dispatcher.cc). Calling plain OnCanWrite() here instead -- as
    // this used to -- leaves that flag stuck set the first time a real
    // write actually blocks (e.g. the kernel send buffer momentarily
    // full under GSO batching with --so_txtime), so every subsequent
    // firing of this same event hits OnCanWrite()'s own internal
    // QUIC_BUG(quic_bug_10511_22) check and fatally closes the
    // connection instead of recovering -- turning one transient block
    // into a permanently dead connection.
    connection_->OnBlockedWriterCanWrite();
    // `&& connection_->IsWriterBlocked()`, not just `!SupportsEdgeTriggered()`
    // alone: a UDP socket is essentially always writable at the OS level, so
    // on this codebase's only event loop implementation (QuicPollEventLoop,
    // poll()-based, SupportsEdgeTriggered() always false -- there's no epoll
    // variant here), unconditionally re-arming for kSocketEventWritable makes
    // RunEventLoopOnce() return immediately on every single call instead of
    // actually sleeping up to its timeout, pinning one CPU core at 100% for
    // as long as this UDP socket exists -- i.e. for the whole lifetime of any
    // connection. Only re-arm when the writer actually still has something
    // it couldn't send, matching the reference pattern in
    // quic_server_io_harness.cc (`dispatcher_.OnCanWrite(); if (... &&
    // dispatcher_.HasPendingWrites()) { RearmSocket(...); }`).
    if (!event_loop_->SupportsEdgeTriggered() &&
        connection_->IsWriterBlocked()) {
      event_loop_->RearmSocket(*udp_fd_, kSocketEventWritable);
    }
  }
}

void QuictunClientConnection::ProcessPacket(
    const QuicSocketAddress& self_address, const QuicSocketAddress& peer_address,
    const QuicReceivedPacket& packet) {
  // Unlike QuictunServerConnection::ProcessPacket(), this doesn't need to
  // override `peer_address` with a cached canonical value: the client's UDP
  // socket is created for `remote_address`'s own address family (see
  // Create()), never a dual-stack wildcard, so QuicPacketReader's
  // v4-mapped-address normalization never disagrees with what the socket
  // actually speaks or what QuicConnection was constructed with.
  connection_->ProcessUdpPacket(self_address, peer_address, packet);
}

}  // namespace quic
