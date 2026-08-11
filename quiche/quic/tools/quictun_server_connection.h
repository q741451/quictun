// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_TOOLS_QUICTUN_SERVER_CONNECTION_H_
#define QUICHE_QUIC_TOOLS_QUICTUN_SERVER_CONNECTION_H_

#include <functional>
#include <memory>
#include <string>

#include "absl/container/flat_hash_map.h"
#include "quiche/quic/core/connecting_client_socket.h"
#include "quiche/quic/core/connection_id_generator.h"
#include "quiche/quic/core/crypto/quic_compressed_certs_cache.h"
#include "quiche/quic/core/crypto/quic_crypto_server_config.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/quic_alarm.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_packet_reader.h"
#include "quiche/quic/core/quic_process_packet_interface.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/socket_factory.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/quictun_session.h"
#include "quiche/quic/tools/quictun_tunnel.h"

namespace quic {

// Server-side mirror of QuictunClientConnection: owns the per-peer UDP
// socket migrated off the rendezvous socket (see quictun_server_driver.h),
// the QuicConnection, and the QuictunServerSession. Each stream the client
// opens on that session (--quic_conn on the client side controls whether
// that's ever more than one -- see quictun_client_driver.h) gets its own
// independent authentication (the --key preamble check), its own dial-out
// to --target, and its own QuictunTunnel -- tracked in stream_targets_,
// keyed by QuicStreamId. A single misbehaving/unauthenticated stream only
// ever affects itself (reset, not the whole connection); the connection
// itself closes on a real QUIC-level failure/idle timeout, or when told to
// by whichever mechanism decides that (there is deliberately no "close when
// the last stream/tunnel ends" logic here -- an empty session with zero
// streams is exactly as valid as a freshly-created one, and stays alive
// until the client either opens another stream on it or lets it idle out;
// that policy question belongs entirely to the client's connection-pooling
// decision, not this class).
class QUICHE_EXPORT QuictunServerConnection : public QuicSession::Visitor,
                                              public QuicSocketEventListener,
                                              public ProcessPacketInterface,
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
  // against each stream's own key preamble once that stream is created --
  // see OnStreamDataAvailable(). `socket_factory` is used to dial --target
  // once (and each time) a stream authenticates -- see
  // StartTunnelForStream(); must outlive this object. Returns nullptr if
  // the dedicated UDP socket couldn't be created/bound/connected -- the
  // caller should just drop the packet in that case.
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
  // Exposed for QuictunServerDriver to apply per-connection startup tuning
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

  // QuicSocketEventListener (for the dedicated UDP socket):
  void OnSocketEvent(QuicEventLoop* event_loop, SocketFd fd,
                     QuicSocketEventMask events) override;

  // ProcessPacketInterface:
  void ProcessPacket(const QuicSocketAddress& self_address,
                     const QuicSocketAddress& peer_address,
                     const QuicReceivedPacket& packet) override;

  // Actually destroys every StreamTarget sitting in closed_stream_targets_
  // -- see that member's comment. Called only from stream_garbage_alarm_
  // (public for the same reason real QUICHE's QuicDispatcher::
  // DeleteSessions() is: its own alarm delegate, a plain top-level class,
  // needs to call it -- see quic_dispatcher.cc's DeleteSessionsAlarm and
  // this file's own StreamGarbageAlarmDelegate). Never called directly by
  // anything else.
  void CollectStreamGarbage();

  // QuictunStreamDelegate: used only during a stream's pre-tunnel
  // authentication phase (reading and validating its key preamble), before
  // a QuictunTunnel exists to take over as that stream's delegate -- see
  // quictun_client_connection.cc for the wire format (2-byte big-endian
  // length + key bytes, always the first bytes on the stream). Not used at
  // all for a stream once StartTunnelForStream() hands its delegate role to
  // the QuictunTunnel that owns it from then on.
  void OnStreamDataAvailable(QuicStreamId id) override;
  void OnStreamCanWriteMore(QuicStreamId /*id*/) override {}
  void OnStreamGone(QuicStreamId id) override;

 private:
  // Per-stream state from the moment a stream authenticates onward: the
  // dial-out to --target and the tunnel pumping bytes between that stream
  // and it. Before authentication, a stream only has an entry in
  // key_read_buffers_ (see OnNewStream()); the two maps are disjoint by
  // construction (StreamAuthenticated() removes from one and adds to the
  // other in the same step).
  struct StreamTarget {
    std::unique_ptr<ConnectingClientSocket> target_socket;
    std::unique_ptr<QuictunTunnel> tunnel;
    // Guards against double Disconnect() on target_socket -- see the
    // comment on Close() and on QuictunTunnel::HasSocket(). Mirrors the
    // pre-multiplexing target_socket_disconnected_ field, now per-stream.
    bool target_socket_disconnected = false;
  };

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

  // SetStreamCreatedCallback() target: starts the new stream's
  // authentication phase (attaches self as its delegate, tries an initial
  // synchronous read in case data already arrived with the same packet
  // that created the stream).
  void OnNewStream(QuicStreamId id);

  // Called once stream `id` has read a full, matching key preamble.
  // `leftover` is any real payload bytes already read past the preamble in
  // the same Read() call. Dials --target and constructs this stream's
  // QuictunTunnel; see the class comment for why this waits for auth
  // first rather than dialing eagerly (avoids wasting a --target
  // connection on a stream that turns out to be unauthenticated, and lets
  // the newly-created QuictunTunnel itself be the dial-out's AsyncVisitor
  // instead of this class needing its own per-stream dial-tracking
  // AsyncVisitor implementation -- see QuictunTunnel::SetSocket()).
  void StartTunnelForStream(QuicStreamId id, QuictunStream* stream,
                            std::string leftover);

  // Disconnects `target.target_socket` if it exists and hasn't been
  // already (idempotency mirrors the pre-multiplexing
  // target_socket_disconnected_ field/logic) -- shared by Close() (tearing
  // every stream's target down when the whole connection goes away) and a
  // stream's own on_closed callback (see StartTunnelForStream()).
  void DisconnectStreamTarget(StreamTarget& target);

  void Close();

  QuicEventLoop* const event_loop_;
  OwnedSocketFd udp_fd_;
  const QuicSocketAddress self_address_;
  const QuicSocketAddress peer_address_;
  const QuicSocketAddress target_address_;
  SocketFactory* const socket_factory_;
  ConnectionIdGeneratorInterface& connection_id_generator_;
  QuicPacketReader reader_;
  std::unique_ptr<QuicConnection> connection_;
  std::unique_ptr<QuictunServerSession> session_;

  const std::string expected_psk_;
  // Streams that have not yet finished authenticating. See the StreamTarget
  // comment for why this and stream_targets_ are disjoint.
  absl::flat_hash_map<QuicStreamId, std::string> key_read_buffers_;
  absl::flat_hash_map<QuicStreamId, StreamTarget> stream_targets_;

  // StreamTargets moved out of stream_targets_ once their tunnel has called
  // its on_closed callback (from StartTunnelForStream()), still fully alive
  // (ownership merely transferred, not destroyed) until stream_garbage_alarm_
  // fires and actually clears this vector. Mirrors real QUICHE's own
  // QuicSession::closed_streams_/closed_streams_clean_up_alarm_
  // (quic_session.cc) exactly: that on_closed callback runs from inside
  // QuictunTunnel::Close(), a member function of the very object
  // stream_targets_ would otherwise destroy synchronously -- moving it here
  // instead (rather than erase()ing it in place) is what lets
  // session_->ClearStreamDelegate(id) (called in that same callback, see
  // StartTunnelForStream()) and this vector's eventual real destruction stay
  // consistent with each other: the delegate pointer this connection handed
  // to session_ is invalidated at the exact same synchronous point the
  // StreamTarget leaves the live map, not some arbitrary later poll -- so
  // there is never a window where session_'s own stream_delegates_ still
  // points at a StreamTarget that either this vector or, later,
  // stream_garbage_alarm_'s firing has already destroyed.
  std::vector<StreamTarget> closed_stream_targets_;

  // Fires once, immediately but outside the current call stack (`Set()` to
  // "now" rather than some future deadline -- see StartTunnelForStream()),
  // to run CollectStreamGarbage() and actually destroy whatever's sitting in
  // closed_stream_targets_. Mirrors QuicSession::closed_streams_clean_up_alarm_
  // exactly, including the same "already set, don't re-arm" check.
  std::unique_ptr<QuicAlarm> stream_garbage_alarm_;

  // Passed to each stream's QuictunTunnel (see its own idle_alarm_ comment)
  // -- read from `config` at construction time since it isn't otherwise
  // available where StartTunnelForStream() constructs each tunnel.
  const QuicTime::Delta idle_timeout_;

  std::function<void(QuictunServerConnection*)> on_closed_;
  bool closed_ = false;
};

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_SERVER_CONNECTION_H_
