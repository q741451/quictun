// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_TOOLS_QUICTUN_CLIENT_CONNECTION_H_
#define QUICHE_QUIC_TOOLS_QUICTUN_CLIENT_CONNECTION_H_

#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
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

// Owns one dedicated QUIC connection over one dedicated UDP socket, and one
// stream (plus QuictunTunnel pumping bytes between that stream and an
// accepted --local TCP connection) per TCP connection assigned to it via
// AssignNewTcp() -- exactly one, ever, if --quic_conn=0 (unchanged from
// quictun's original one-connection-per-tunnel design), or possibly many
// over this object's lifetime if --quic_conn pools connections (see
// quictun_client_driver.h). Constructed by QuictunClientDriver; destroyed
// (by the driver, via the on_closed callback) once the whole QUIC
// connection closes for any reason -- not when any single stream's tunnel
// finishes; see AssignNewTcp() and the class comment on
// QuictunServerConnection for the server-side mirror of this same policy.
class QUICHE_EXPORT QuictunClientConnection : public QuicSession::Visitor,
                                              public QuicSocketEventListener,
                                              public ProcessPacketInterface {
 public:
  // Returns nullptr if the UDP socket for this connection couldn't be
  // created or connected -- the caller should not call AssignNewTcp() in
  // that case. `helper`, `alarm_factory`, `connection_id_generator`,
  // `crypto_config`, and `buffer_allocator` are shared across every
  // QuictunClientConnection the driver creates and must outlive this
  // object; `config` is copied. Does not itself accept any TCP connection --
  // call AssignNewTcp() once (--quic_conn=0) or repeatedly (pooling) after
  // construction.
  static std::unique_ptr<QuictunClientConnection> Create(
      QuicEventLoop* event_loop, QuicConnectionHelperInterface* helper,
      QuicAlarmFactory* alarm_factory,
      ConnectionIdGeneratorInterface& connection_id_generator,
      quiche::QuicheBufferAllocator* buffer_allocator, const QuicConfig& config,
      const QuicServerId& server_id, const QuicSocketAddress& remote_address,
      QuicCryptoClientConfig* crypto_config, const std::string& psk,
      CongestionControlType congestion_control, bool so_txtime_enabled,
      QuicByteCount udp_socket_buffer_bytes,
      std::function<void(QuictunClientConnection*)> on_closed);

  ~QuictunClientConnection() override;

  // Assigns one more accepted --local TCP connection to this QUIC
  // connection, as a new outgoing stream. `accepted_tcp_fd` must be an
  // already-accepted, connected TCP socket; ownership passes to this
  // object (which will close it eventually, one way or another -- there is
  // no failure return that leaves the caller still responsible for it).
  // Queues if a new stream can't be opened immediately (no 0-RTT session
  // yet and the handshake hasn't supplied a max_streams value, or the
  // negotiated/granted stream count is temporarily exhausted); multiple
  // TCPs can be queued at once (relevant only under --quic_conn pooling --
  // --quic_conn=0 only ever calls this once per connection, so there's
  // never more than one pending at a time there). No-op (closes
  // `accepted_tcp_fd` immediately) if this connection is already closed --
  // callers doing their own pooling should check closed()/query state
  // through the driver, not rely on this to signal that.
  void AssignNewTcp(SocketFd accepted_tcp_fd,
                    const QuicSocketAddress& tcp_peer_address);

  // Exposed for QuictunClientDriver to apply per-connection startup tuning
  // (see SetQuictunStartupBandwidthHint()) right after construction, and
  // (under --quic_conn pooling) to know whether this connection is still
  // eligible to have more TCPs assigned to it -- see quictun_client_driver.cc.
  QuicConnection* connection() const { return connection_.get(); }
  bool closed() const { return closed_; }

  // Destroys the StreamTcp (and thus the QuictunTunnel and tcp_socket) for
  // any stream whose tunnel closed itself since the last call -- mirrors
  // QuictunServerConnection::CollectStreamGarbage() exactly (see its
  // comment for why this can't happen synchronously from within a tunnel's
  // own on_closed callback). Must be called once per event-loop iteration,
  // from outside any callback originating from this connection or any of
  // its tunnels -- see QuictunClientDriver::CollectGarbage(), which is what
  // actually calls this, once per iteration, for every still-live
  // connection.
  void CollectStreamGarbage();

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
  // One TCP connection's fd, waiting in pending_tcps_ for a stream to open.
  struct PendingTcp {
    SocketFd fd;
    QuicSocketAddress peer_address;
  };

  // One stream's TCP-pumping state, from the moment its stream opens
  // onward -- mirrors QuictunServerConnection::StreamTarget.
  struct StreamTcp {
    std::unique_ptr<QuictunAcceptedTcpSocket> tcp_socket;
    std::unique_ptr<QuictunTunnel> tunnel;
    bool tcp_socket_disconnected = false;
  };

  QuictunClientConnection(
      QuicEventLoop* event_loop, OwnedSocketFd udp_fd,
      const QuicSocketAddress& self_address,
      const QuicSocketAddress& remote_address, QuicConnectionHelperInterface* helper,
      QuicAlarmFactory* alarm_factory,
      ConnectionIdGeneratorInterface& connection_id_generator,
      quiche::QuicheBufferAllocator* buffer_allocator, const QuicConfig& config,
      const QuicServerId& server_id, QuicCryptoClientConfig* crypto_config,
      const std::string& psk, CongestionControlType congestion_control,
      bool so_txtime_enabled,
      std::function<void(QuictunClientConnection*)> on_closed);

  // Opens outgoing streams for as many of pending_tcps_ as currently
  // possible (usually zero or one at a time -- see
  // QuicSession::Visitor::OnCanCreateNewOutgoingStream()/
  // SetCanOpenStreamCallback()'s comment -- but drains as many as it can in
  // one call in case a MAX_STREAMS frame grants several at once). Safe to
  // call any time, including with an empty queue. Called once right after
  // CryptoConnect() (succeeds immediately for anything already queued if a
  // cached 0-RTT session already supplied a max_streams value), again from
  // AssignNewTcp() for each newly-queued TCP, and again from the session's
  // can-open-stream callback whenever QuicSession applies a new max_streams
  // value.
  void MaybeOpenStreams();

  // Writes the --key auth preamble and wires up this stream's StreamTcp
  // entry for the TCP connection `pending`.
  void StartTunnel(QuictunStream* stream, PendingTcp pending);

  void Close();

  QuicEventLoop* const event_loop_;
  OwnedSocketFd udp_fd_;
  const QuicSocketAddress self_address_;
  QuicPacketReader reader_;
  std::unique_ptr<QuicConnection> connection_;
  std::unique_ptr<QuictunClientSession> session_;

  const std::string psk_;
  quiche::QuicheBufferAllocator* const buffer_allocator_;
  std::deque<PendingTcp> pending_tcps_;
  absl::flat_hash_map<QuicStreamId, StreamTcp> stream_tcps_;
  // See QuictunServerConnection::pending_stream_removal_'s comment --
  // identical rationale, mirrored one class over.
  std::vector<QuicStreamId> pending_stream_removal_;

  // Passed to each stream's QuictunTunnel (see its own idle_alarm_ comment)
  // -- read from `config` at construction time since it isn't otherwise
  // available where StartTunnel() constructs each tunnel.
  const QuicTime::Delta idle_timeout_;

  std::function<void(QuictunClientConnection*)> on_closed_;
  bool closed_ = false;
};

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_CLIENT_CONNECTION_H_
