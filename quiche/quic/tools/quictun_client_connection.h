// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_TOOLS_QUICTUN_CLIENT_CONNECTION_H_
#define QUICHE_QUIC_TOOLS_QUICTUN_CLIENT_CONNECTION_H_

#include <functional>
#include <memory>
#include <string>

#include "quiche/quic/core/connection_id_generator.h"
#include "quiche/quic/core/crypto/quic_crypto_client_config.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_packet_reader.h"
#include "quiche/quic/core/quic_process_packet_interface.h"
#include "quiche/quic/core/quic_server_id.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/quictun_accepted_tcp_socket.h"
#include "quiche/quic/tools/quictun_session.h"
#include "quiche/quic/tools/quictun_tunnel.h"
#include "quiche/common/quiche_buffer_allocator.h"

namespace quic {

// Owns everything for tunneling exactly one accepted --local TCP connection
// over exactly one dedicated QUIC connection over exactly one dedicated UDP
// socket: the UDP socket, the QuicConnection, the QuictunClientSession, and
// the QuictunTunnel pumping bytes between the session's one stream and the
// accepted TCP fd. Constructed by QuictunClientDriver for each accepted
// connection; destroyed (by the driver, via the on_closed callback) once the
// tunnel closes for any reason.
class QUICHE_EXPORT QuictunClientConnection : public QuicSession::Visitor,
                                              public QuicSocketEventListener,
                                              public ProcessPacketInterface {
 public:
  // Returns nullptr if the UDP socket for this tunnel couldn't be created or
  // connected -- the caller should just drop the accepted TCP connection
  // (closing `accepted_tcp_fd`) in that case. `helper`, `alarm_factory`,
  // `connection_id_generator`, `crypto_config`, and `buffer_allocator` are
  // shared across every tunnel the driver creates and must outlive this
  // object; `config` is copied.
  static std::unique_ptr<QuictunClientConnection> Create(
      QuicEventLoop* event_loop, QuicConnectionHelperInterface* helper,
      QuicAlarmFactory* alarm_factory,
      ConnectionIdGeneratorInterface& connection_id_generator,
      quiche::QuicheBufferAllocator* buffer_allocator, const QuicConfig& config,
      const QuicServerId& server_id, const QuicSocketAddress& remote_address,
      QuicCryptoClientConfig* crypto_config, const std::string& psk,
      CongestionControlType congestion_control, bool so_txtime_enabled,
      QuicByteCount udp_socket_buffer_bytes, SocketFd accepted_tcp_fd,
      const QuicSocketAddress& tcp_peer_address,
      std::function<void(QuictunClientConnection*)> on_closed);

  ~QuictunClientConnection() override;

  // Exposed for QuictunClientDriver to apply per-connection startup tuning
  // (see SetQuictunStartupBandwidthHint()) right after construction.
  QuicConnection* connection() const { return connection_.get(); }

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

  // QuicSocketEventListener:
  void OnSocketEvent(QuicEventLoop* event_loop, SocketFd fd,
                     QuicSocketEventMask events) override;

  // ProcessPacketInterface:
  void ProcessPacket(const QuicSocketAddress& self_address,
                     const QuicSocketAddress& peer_address,
                     const QuicReceivedPacket& packet) override;

 private:
  QuictunClientConnection(
      QuicEventLoop* event_loop, OwnedSocketFd udp_fd,
      const QuicSocketAddress& self_address,
      const QuicSocketAddress& remote_address, QuicConnectionHelperInterface* helper,
      QuicAlarmFactory* alarm_factory,
      ConnectionIdGeneratorInterface& connection_id_generator,
      quiche::QuicheBufferAllocator* buffer_allocator, const QuicConfig& config,
      const QuicServerId& server_id, QuicCryptoClientConfig* crypto_config,
      const std::string& psk, CongestionControlType congestion_control,
      bool so_txtime_enabled, SocketFd accepted_tcp_fd,
      const QuicSocketAddress& tcp_peer_address,
      std::function<void(QuictunClientConnection*)> on_closed);

  // Tries to open the tunnel's one outgoing stream if it hasn't been opened
  // yet, and if successful, starts the tunnel on it. Safe to call
  // repeatedly: once optimistically right after CryptoConnect() (succeeds
  // immediately when a cached 0-RTT session already supplied a max_streams
  // value), then again from the session's can-open-stream callback (see
  // QuictunClientSession::SetCanOpenStreamCallback) once a fresh, non-0-RTT
  // connection's negotiated transport parameters make it possible.
  void MaybeOpenStream();

  // Writes the --key auth preamble and wires up tcp_socket_/tunnel_ for an
  // already-opened `stream`.
  void StartTunnel(QuictunStream* stream);

  void Close();

  QuicEventLoop* const event_loop_;
  OwnedSocketFd udp_fd_;
  const QuicSocketAddress self_address_;
  QuicPacketReader reader_;
  std::unique_ptr<QuicConnection> connection_;
  std::unique_ptr<QuictunClientSession> session_;
  std::unique_ptr<QuictunAcceptedTcpSocket> tcp_socket_;
  std::unique_ptr<QuictunTunnel> tunnel_;
  // See the identical target_socket_disconnected_ comment in
  // quictun_server_connection.h -- same rationale, same fix.
  bool tcp_socket_disconnected_ = false;

  const std::string psk_;
  quiche::QuicheBufferAllocator* const buffer_allocator_;
  const SocketFd accepted_tcp_fd_;
  const QuicSocketAddress tcp_peer_address_;
  bool stream_opened_ = false;

  // Passed to QuictunTunnel's own idle-timeout mechanism (see its comment on
  // idle_alarm_) -- read from `config` at construction time since it isn't
  // otherwise available where StartTunnel() constructs the tunnel.
  const QuicTime::Delta idle_timeout_;

  std::function<void(QuictunClientConnection*)> on_closed_;
  bool closed_ = false;
};

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_CLIENT_CONNECTION_H_
