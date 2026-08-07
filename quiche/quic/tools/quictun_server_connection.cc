// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_server_connection.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_framer.h"
#include "quiche/quic/core/quic_packet_writer.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/tools/quictun_connection_factory.h"
#include "quiche/quic/tools/quictun_socket_util.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace quic {

std::unique_ptr<QuictunServerConnection> QuictunServerConnection::Create(
    QuicEventLoop* event_loop, QuicConnectionHelperInterface* helper,
    QuicAlarmFactory* alarm_factory, SocketFactory* socket_factory,
    ConnectionIdGeneratorInterface& connection_id_generator,
    const QuicConfig& config, const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache,
    const QuicSocketAddress& listen_address, const QuicSocketAddress& self_address,
    const QuicSocketAddress& peer_address,
    const QuicSocketAddress& target_address, QuicConnectionId server_connection_id,
    const std::string& psk, CongestionControlType congestion_control,
    bool so_txtime_enabled, QuicByteCount udp_socket_buffer_bytes,
    const QuicReceivedPacket& first_packet,
    std::function<void(QuictunServerConnection*)> on_closed) {
  absl::StatusOr<OwnedSocketFd> fd =
      CreateReusableUdpSocket(listen_address, udp_socket_buffer_bytes);
  if (!fd.ok()) {
    QUIC_LOG(ERROR) << "Failed to create per-connection UDP socket for "
                    << peer_address << ": " << fd.status();
    return nullptr;
  }
  OwnedSocketFd udp_fd = *std::move(fd);

  absl::Status bind_status = socket_api::Bind(*udp_fd, listen_address);
  if (!bind_status.ok()) {
    QUIC_LOG(ERROR) << "Failed to bind per-connection UDP socket to "
                    << listen_address << ": " << bind_status;
    return nullptr;
  }

  absl::Status connect_status = socket_api::Connect(*udp_fd, peer_address);
  if (!connect_status.ok()) {
    QUIC_LOG(ERROR) << "Failed to connect per-connection UDP socket to "
                    << peer_address << ": " << connect_status;
    return nullptr;
  }

  return absl::WrapUnique(new QuictunServerConnection(
      event_loop, std::move(udp_fd), self_address, peer_address, helper,
      alarm_factory, socket_factory, connection_id_generator, config,
      crypto_config, compressed_certs_cache, target_address,
      server_connection_id, psk, congestion_control, so_txtime_enabled,
      first_packet, std::move(on_closed)));
}

QuictunServerConnection::QuictunServerConnection(
    QuicEventLoop* event_loop, OwnedSocketFd udp_fd,
    const QuicSocketAddress& self_address, const QuicSocketAddress& peer_address,
    QuicConnectionHelperInterface* helper, QuicAlarmFactory* alarm_factory,
    SocketFactory* socket_factory,
    ConnectionIdGeneratorInterface& connection_id_generator,
    const QuicConfig& config, const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache,
    const QuicSocketAddress& target_address, QuicConnectionId server_connection_id,
    const std::string& psk, CongestionControlType congestion_control,
    bool so_txtime_enabled, const QuicReceivedPacket& first_packet,
    std::function<void(QuictunServerConnection*)> on_closed)
    : event_loop_(event_loop),
      udp_fd_(std::move(udp_fd)),
      self_address_(self_address),
      peer_address_(peer_address),
      connection_id_generator_(connection_id_generator),
      expected_psk_(psk),
      on_closed_(std::move(on_closed)) {
  std::unique_ptr<QuicPacketWriter> writer =
      MakeQuictunPacketWriter(*udp_fd_, so_txtime_enabled);

  connection_ = std::make_unique<QuicConnection>(
      server_connection_id, self_address_, peer_address_, helper, alarm_factory,
      writer.release(), /*owns_writer=*/true, Perspective::IS_SERVER,
      GetQuictunVersions(), connection_id_generator);
  SetQuictunCongestionControl(connection_.get(), congestion_control);

  session_ = std::make_unique<QuictunServerSession>(
      connection_.get(), /*owner=*/this, config, "quictun/1", crypto_config,
      compressed_certs_cache);
  session_->Initialize();

  bool registered = event_loop_->RegisterSocket(
      *udp_fd_, kSocketEventReadable | kSocketEventWritable, this);
  QUICHE_DCHECK(registered);

  connection_->ProcessUdpPacket(self_address_, peer_address_, first_packet);
  if (closed_) {
    // Processing the first packet already synchronously failed the
    // connection (e.g. a write error) and ran Close(), which invoked
    // on_closed_ -- the driver has queued this object for destruction.
    // Don't dial --target for a connection that's already dead: nothing
    // would ever call Disconnect() on it afterward.
    return;
  }
  MaybeStartTunnel();

  target_socket_ = socket_factory->CreateTcpClientSocket(
      target_address, /*receive_buffer_size=*/0, /*send_buffer_size=*/0, this);
  target_socket_->ConnectAsync();
}

QuictunServerConnection::~QuictunServerConnection() {
  event_loop_->UnregisterSocket(*udp_fd_);
}

void QuictunServerConnection::Close() {
  if (closed_) {
    return;
  }
  closed_ = true;
  if (connection_->connected()) {
    connection_->CloseConnection(
        QUIC_NO_ERROR, "quictun tunnel closed",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  }
  if (target_socket_ && !target_socket_disconnected_) {
    target_socket_disconnected_ = true;
    target_socket_->Disconnect();
  }
  event_loop_->UnregisterSocket(*udp_fd_);
  std::function<void(QuictunServerConnection*)> on_closed = std::move(on_closed_);
  if (on_closed) {
    on_closed(this);
  }
}

void QuictunServerConnection::OnConnectionClosed(
    QuicConnectionId /*server_connection_id*/, QuicErrorCode /*error*/,
    const std::string& /*error_details*/, ConnectionCloseSource /*source*/) {
  Close();
}

void QuictunServerConnection::OnSocketEvent(QuicEventLoop* /*event_loop*/,
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
  MaybeStartTunnel();
}

void QuictunServerConnection::ProcessPacket(
    const QuicSocketAddress& self_address,
    const QuicSocketAddress& /*peer_address*/, const QuicReceivedPacket& packet) {
  // This dedicated, connect()ed UDP socket can only ever receive packets
  // from peer_address_ -- but that doesn't mean every packet that lands
  // here truly belongs to *this* QUIC connection. Once this connection is
  // torn down server-side (deferred via pending_removal_/CollectGarbage(),
  // see quictun_server_driver.cc), its socket/connect() 4-tuple claim isn't
  // released until the next garbage-collection pass, and UDP source ports
  // have no TCP-style TIME_WAIT delay -- so the client's OS can reuse the
  // exact same ephemeral port for a brand-new connection within
  // milliseconds, and the kernel will keep routing that peer's packets
  // straight to this now-stale socket, bypassing the rendezvous socket (and
  // QuictunServerDriver::ProcessPacket's own same-check) entirely. Forwarding
  // such a packet into a QuicConnection that doesn't recognize its
  // connection ID hits a fatal QUICHE_DCHECK in quic_connection.cc that
  // assumes a server can never see this (an assumption that only holds with
  // a real QuicDispatcher demuxing by connection ID up front, which quictun
  // deliberately doesn't have). Detect and silently drop that case here --
  // the new client's retransmissions will succeed once this connection's
  // socket is actually closed and the 4-tuple frees up, letting them reach
  // the rendezvous socket and be recognized there as a genuinely new
  // connection. Not just Initial packets: once a misrouted new connection's
  // Initial slips through, ITS follow-up Handshake/1-RTT packets would
  // arrive at this same stale socket too (same misrouted 4-tuple) before
  // the client ever hears back -- so every packet's connection ID is
  // checked here, not only long-header Initial ones.
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
  QuicErrorCode header_error =
      QuicFramer::ParsePublicHeaderDispatcherShortHeaderLengthUnknown(
          packet, &format, &long_packet_type, &version_present,
          &has_length_prefix, &version_label, &parsed_version,
          &destination_connection_id, &source_connection_id, &retry_token,
          &detailed_error, connection_id_generator_);
  if (header_error == QUIC_NO_ERROR && !destination_connection_id.empty() &&
      QuicConnectionId(destination_connection_id) != connection_->connection_id()) {
    QUIC_LOG(INFO) << "Dropping packet for unrecognized connection ID "
                   << QuicConnectionId(destination_connection_id) << " from "
                   << peer_address_ << " on stale connection "
                   << connection_->connection_id()
                   << "'s socket -- peer reused its address, retry will "
                      "reach the rendezvous socket once this connection is "
                      "garbage-collected";
    return;
  }
  connection_->ProcessUdpPacket(self_address, peer_address_, packet);
}

void QuictunServerConnection::ConnectComplete(absl::Status status) {
  if (tunnel_) {
    tunnel_->ConnectComplete(status);
    return;
  }
  if (!status.ok()) {
    QUIC_LOG(WARNING) << "Failed to connect to target for " << peer_address_
                      << ": " << status;
    // A failed async connect already tears the socket down internally (see
    // EventLoopConnectingClientSocket::FinishOrRearmAsyncConnect(), which
    // calls its private Close() before invoking this callback with an error
    // status) -- calling target_socket_->Disconnect() again from Close()
    // below would hit a fatal descriptor_ != kInvalidSocketFd check.
    target_socket_disconnected_ = true;
    Close();
    return;
  }
  target_connected_ = true;
  MaybeStartTunnel();
}

void QuictunServerConnection::ReceiveComplete(
    absl::StatusOr<quiche::QuicheMemSlice> data) {
  QUICHE_DCHECK(tunnel_);
  tunnel_->ReceiveComplete(std::move(data));
}

void QuictunServerConnection::SendComplete(absl::Status status) {
  QUICHE_DCHECK(tunnel_);
  tunnel_->SendComplete(status);
}

void QuictunServerConnection::MaybeStartTunnel() {
  if (tunnel_ || closed_ || session_->stream() == nullptr) {
    return;
  }
  if (!auth_delegate_attached_) {
    // First time the stream exists: start reading it ourselves to validate
    // the key preamble, independently of (and possibly before) the --target
    // dial-out finishing.
    auth_delegate_attached_ = true;
    session_->SetStreamDelegate(this);
    OnStreamDataAvailable();
    return;
  }
  if (!authenticated_ || !target_connected_) {
    return;
  }
  tunnel_ = std::make_unique<QuictunTunnel>(
      session_->stream(), target_socket_.get(), [this] {
        // QuictunTunnel::Close() already disconnected target_socket_ before
        // invoking this callback -- see the comment on
        // target_socket_disconnected_.
        target_socket_disconnected_ = true;
        Close();
      });
  session_->SetStreamDelegate(tunnel_.get());
  tunnel_->Start(key_read_buffer_);
  key_read_buffer_.clear();
}

void QuictunServerConnection::OnStreamDataAvailable() {
  if (authenticated_ || closed_) {
    return;
  }
  QuictunStream* stream = session_->stream();
  char buffer[512];
  bool fin = false;
  while (!authenticated_) {
    size_t bytes_read = stream->Read(absl::MakeSpan(buffer, sizeof(buffer)), &fin);
    if (bytes_read > 0) {
      key_read_buffer_.append(buffer, bytes_read);
    }
    if (key_read_buffer_.size() >= 2) {
      size_t key_length = (static_cast<uint8_t>(key_read_buffer_[0]) << 8) |
                          static_cast<uint8_t>(key_read_buffer_[1]);
      if (key_read_buffer_.size() >= 2 + key_length) {
        absl::string_view received_key(key_read_buffer_.data() + 2, key_length);
        if (received_key != expected_psk_) {
          QUIC_LOG(WARNING) << "Rejecting connection from " << peer_address_
                            << ": key mismatch";
          Close();
          return;
        }
        authenticated_ = true;
        // Any bytes already read past the preamble are real payload; hand
        // them to the tunnel once it's constructed (see MaybeStartTunnel()).
        key_read_buffer_ = key_read_buffer_.substr(2 + key_length);
        break;
      }
    }
    if (bytes_read == 0) {
      break;
    }
  }
  if (fin && !authenticated_) {
    QUIC_LOG(WARNING) << "Connection from " << peer_address_
                      << " closed before completing authentication";
    Close();
    return;
  }
  MaybeStartTunnel();
}

void QuictunServerConnection::OnStreamClosed() {
  // Only relevant during the pre-tunnel auth phase (once a QuictunTunnel
  // exists, it -- not this class -- is the stream's delegate).
  Close();
}

}  // namespace quic
