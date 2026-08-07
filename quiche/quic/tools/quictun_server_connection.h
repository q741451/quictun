// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_TOOLS_QUICTUN_SERVER_CONNECTION_H_
#define QUICHE_QUIC_TOOLS_QUICTUN_SERVER_CONNECTION_H_

#include <functional>
#include <memory>
#include <string>

#include "quiche/quic/core/connecting_client_socket.h"
#include "quiche/quic/core/connection_id_generator.h"
#include "quiche/quic/core/crypto/quic_compressed_certs_cache.h"
#include "quiche/quic/core/crypto/quic_crypto_server_config.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_packet_reader.h"
#include "quiche/quic/core/quic_process_packet_interface.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/socket_factory.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/quictun_session.h"
#include "quiche/quic/tools/quictun_tunnel.h"

namespace quic {

// Server-side mirror of QuictunClientConnection: owns the per-peer UDP
// socket migrated off the rendezvous socket (see quictun_server_driver.h),
// the QuicConnection, the QuictunServerSession, the outbound TCP connection
// to --target, and the QuictunTunnel pumping bytes between the session's
// one stream and that TCP connection.
//
// Two independent things must both be ready before the tunnel can start:
// the QUIC stream (opened by the client once its handshake/0-RTT flight
// goes out -- quictun's client always opens the stream, per
// quictun_client_connection.cc) and the TCP dial-out to --target
// completing. This class acts as the AsyncVisitor for that dial-out itself
// (rather than handing the socket straight to a QuictunTunnel, which
// doesn't exist yet) and forwards to the tunnel once both are ready and it
// has been constructed.
class QUICHE_EXPORT QuictunServerConnection : public QuicSession::Visitor,
                                              public QuicSocketEventListener,
                                              public ProcessPacketInterface,
                                              public ConnectingClientSocket::AsyncVisitor,
                                              public QuictunStreamDelegate {
 public:
  // `listen_address` is the address the new per-connection socket binds to
  // (the wildcard --listen address, shared with the rendezvous socket via
  // SO_REUSEADDR/SO_REUSEPORT -- see quictun_socket_util.h). `self_address`
  // is the real, specific local IP the first packet actually arrived on, as
  // resolved per-packet by QuicPacketReader from IP_PKTINFO/IPV6_PKTINFO
  // ancillary data -- this, not the wildcard bind address, is what gets
  // handed to QuicConnection: passing the wildcard there causes outgoing
  // writes to fail with EINVAL (self-IP info in the cmsg on outgoing
  // packets must be a concrete address, matching the socket's protocol
  // family, not "::"/"0.0.0.0"). `first_packet` is fed into the new
  // QuicConnection immediately. `psk` (the server's own --key) is checked
  // against the client's key preamble once the stream is created -- see
  // OnStreamDataAvailable(). Returns nullptr if the dedicated UDP socket
  // couldn't be created/bound/connected -- the caller should just drop the
  // packet in that case.
  static std::unique_ptr<QuictunServerConnection> Create(
      QuicEventLoop* event_loop, QuicConnectionHelperInterface* helper,
      QuicAlarmFactory* alarm_factory, SocketFactory* socket_factory,
      ConnectionIdGeneratorInterface& connection_id_generator,
      const QuicConfig& config, const QuicCryptoServerConfig* crypto_config,
      QuicCompressedCertsCache* compressed_certs_cache,
      const QuicSocketAddress& listen_address,
      const QuicSocketAddress& self_address,
      const QuicSocketAddress& peer_address,
      const QuicSocketAddress& target_address,
      QuicConnectionId server_connection_id, const std::string& psk,
      CongestionControlType congestion_control, bool so_txtime_enabled,
      QuicByteCount udp_socket_buffer_bytes,
      const QuicReceivedPacket& first_packet,
      std::function<void(QuictunServerConnection*)> on_closed);

  ~QuictunServerConnection() override;

  const QuicSocketAddress& peer_address() const { return peer_address_; }
  const QuicConnectionId& connection_id() const {
    return connection_->connection_id();
  }

  // QuicSession::Visitor:
  void OnConnectionClosed(QuicConnectionId server_connection_id,
                          QuicErrorCode error, const std::string& error_details,
                          ConnectionCloseSource source) override;
  void OnWriteBlocked(QuicBlockedWriterInterface* blocked_writer) override {}
  void OnRstStreamReceived(const QuicRstStreamFrame& frame) override {}
  void OnStopSendingReceived(const QuicStopSendingFrame& frame) override {}
  bool TryAddNewConnectionId(
      const QuicConnectionId& server_connection_id,
      const QuicConnectionId& new_connection_id) override {
    return false;
  }
  void OnConnectionIdRetired(
      const QuicConnectionId& server_connection_id) override {}
  void OnServerPreferredAddressAvailable(
      const QuicSocketAddress& server_preferred_address) override {}
  void OnPathDegrading() override {}
  void OnConfigNegotiated(const QuicConfig& config) override {}

  // QuicSocketEventListener (for the dedicated UDP socket):
  void OnSocketEvent(QuicEventLoop* event_loop, SocketFd fd,
                     QuicSocketEventMask events) override;

  // ProcessPacketInterface:
  void ProcessPacket(const QuicSocketAddress& self_address,
                     const QuicSocketAddress& peer_address,
                     const QuicReceivedPacket& packet) override;

  // ConnectingClientSocket::AsyncVisitor (dial-out to --target; forwarded to
  // tunnel_ once it exists -- see class comment):
  void ConnectComplete(absl::Status status) override;
  void ReceiveComplete(absl::StatusOr<quiche::QuicheMemSlice> data) override;
  void SendComplete(absl::Status status) override;

  // QuictunStreamDelegate: used only during the pre-tunnel authentication
  // phase (reading and validating the client's key preamble), before a
  // QuictunTunnel exists to take over as the stream's delegate -- see
  // quictun_client_connection.cc for the wire format (2-byte big-endian
  // length + key bytes, always the first bytes on the stream).
  void OnStreamDataAvailable() override;
  void OnStreamCanWriteMore() override {}
  void OnStreamClosed() override;

 private:
  QuictunServerConnection(
      QuicEventLoop* event_loop, OwnedSocketFd udp_fd,
      const QuicSocketAddress& self_address, const QuicSocketAddress& peer_address,
      QuicConnectionHelperInterface* helper, QuicAlarmFactory* alarm_factory,
      SocketFactory* socket_factory,
      ConnectionIdGeneratorInterface& connection_id_generator,
      const QuicConfig& config, const QuicCryptoServerConfig* crypto_config,
      QuicCompressedCertsCache* compressed_certs_cache,
      const QuicSocketAddress& target_address,
      QuicConnectionId server_connection_id, const std::string& psk,
      CongestionControlType congestion_control, bool so_txtime_enabled,
      const QuicReceivedPacket& first_packet,
      std::function<void(QuictunServerConnection*)> on_closed);

  void MaybeStartTunnel();
  void Close();

  QuicEventLoop* const event_loop_;
  OwnedSocketFd udp_fd_;
  const QuicSocketAddress self_address_;
  const QuicSocketAddress peer_address_;
  ConnectionIdGeneratorInterface& connection_id_generator_;
  QuicPacketReader reader_;
  std::unique_ptr<QuicConnection> connection_;
  std::unique_ptr<QuictunServerSession> session_;
  std::unique_ptr<ConnectingClientSocket> target_socket_;
  std::unique_ptr<QuictunTunnel> tunnel_;
  bool target_connected_ = false;
  // Set right before Close() is invoked via the tunnel's on_closed callback
  // (at that point the tunnel has already called target_socket_->
  // Disconnect() itself) -- guards Close()'s own unconditional disconnect
  // so it never double-disconnects (fatal: EventLoopConnectingClientSocket::
  // Disconnect() asserts it isn't already disconnected) but still reliably
  // disconnects when closure originates from somewhere other than the
  // tunnel (e.g. OnConnectionClosed firing from a QUIC-level failure while
  // the TCP dial-out is still in flight or the tunnel hasn't detected
  // anything wrong on its own side yet).
  bool target_socket_disconnected_ = false;

  const std::string expected_psk_;
  bool auth_delegate_attached_ = false;
  bool authenticated_ = false;
  std::string key_read_buffer_;

  std::function<void(QuictunServerConnection*)> on_closed_;
  bool closed_ = false;
};

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_SERVER_CONNECTION_H_
