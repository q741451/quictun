// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_TOOLS_QUICTUN_SERVER_DRIVER_H_
#define QUICHE_QUIC_TOOLS_QUICTUN_SERVER_DRIVER_H_

#include <memory>
#include <optional>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "openssl/siphash.h"
#include "quiche/quic/core/crypto/quic_compressed_certs_cache.h"
#include "quiche/quic/core/crypto/quic_crypto_server_config.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/deterministic_connection_id_generator.h"
#include "quiche/quic/core/io/event_loop_socket_factory.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_default_connection_helper.h"
#include "quiche/quic/core/quic_blocked_writer_list.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_packet_reader.h"
#include "quiche/quic/core/quic_process_packet_interface.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/quictun_flags.h"
#include "quiche/quic/tools/quictun_server_connection.h"

namespace quic {

// Owns the one UDP socket on --listen, its reader and its writer, and
// routes each packet to a QuictunServerConnection by destination connection
// ID -- QuicDispatcher's shape (see quic_server_io_harness.cc for the
// upstream equivalent of the socket handling), without QuicDispatcher
// itself, whose QuicSession-shaped connection model quictun does not use.
// Also owns the state shared
// by every connection: the crypto config (with the auto-generated
// self-signed cert and PSK), the compressed-certs cache, the connection
// helper/alarm factory/connection-ID generator, the TCP socket factory used
// to dial --target, and the QuicConfig template.
class QUICHE_EXPORT QuictunServerDriver : public QuicSocketEventListener,
                                          public ProcessPacketInterface {
 public:
  // `target_address` is nullopt iff `options.transparent` -- in that mode
  // there is no single fixed target, each QuictunServerConnection connects
  // out to a per-stream destination captured by the client instead (see
  // quictun_server_connection.h).
  QuictunServerDriver(QuicEventLoop* event_loop,
                      const QuicSocketAddress& listen_address,
                      std::optional<QuicSocketAddress> target_address,
                      const QuictunTuningOptions& options,
                      int32_t max_new_connections_per_event_loop,
                      int32_t max_concurrent_connections);

  // Creates, binds, and registers the listen UDP socket. Returns
  // non-ok on failure.
  absl::Status Start();

  // QuicSocketEventListener (for the listen UDP socket):
  void OnSocketEvent(QuicEventLoop* event_loop, SocketFd fd,
                     QuicSocketEventMask events) override;

  // ProcessPacketInterface (for the listen UDP socket):
  void ProcessPacket(const QuicSocketAddress& self_address,
                     const QuicSocketAddress& peer_address,
                     const QuicReceivedPacket& packet) override;

  // See QuictunClientDriver::CollectGarbage() -- identical rationale:
  // QuictunServerConnection::Close() can't safely destroy itself
  // synchronously from within its own callback stack. Also resets
  // new_connections_allowed_this_event_loop_ for the next iteration --
  // see that member's comment.
  // Called by a connection whose write hit the shared socket's full send
  // buffer; drained in OnSocketEvent() when it reports writable again.
  void OnWriteBlocked(QuicBlockedWriterInterface* blocked_writer);

  void CollectGarbage();

  // Closes every tunnel that has gone quiet for --tcp_idle_timeout_seconds.
  // Called once per event-loop iteration alongside CollectGarbage(), and
  // for the same reason it lives there rather than in an alarm: closing a
  // tunnel reenters its owner, so it has to happen at a point where no
  // tunnel's or connection's own call stack is still unwinding. Costs one
  // comparison when nothing has expired -- see QuictunIdleTracker.
  void CloseIdleTunnels();


 private:
  void RemoveConnection(QuictunServerConnection* connection);

  QuicEventLoop* const event_loop_;
  const QuicSocketAddress listen_address_;
  const std::optional<QuicSocketAddress> target_address_;
  const QuictunTuningOptions options_;
  const int32_t max_new_connections_per_event_loop_;
  const int32_t max_concurrent_connections_;

  OwnedSocketFd listen_fd_;
  // Shared by every QuictunServerConnection; must outlive connections_.
  std::unique_ptr<QuicPacketWriter> shared_writer_;
  // Every connection that hit a blocked write on the shared socket, drained
  // when the event loop reports it writable again -- exactly
  // QuicDispatcher::write_blocked_list_'s role. With one socket for all
  // connections there is no per-connection writability event any more, so
  // without this a full send buffer would wedge the whole process.
  QuicBlockedWriterList write_blocked_list_;
  QuicPacketReader reader_;

  QuicDefaultConnectionHelper helper_;
  std::unique_ptr<QuicAlarmFactory> alarm_factory_;
  DeterministicConnectionIdGenerator connection_id_generator_;
  QuicConfig config_template_;
  std::unique_ptr<QuicCryptoServerConfig> crypto_config_;
  QuicCompressedCertsCache compressed_certs_cache_;
  EventLoopSocketFactory socket_factory_;
  CongestionControlType congestion_control_;

  // Every live tunnel across every connection this driver owns. Must
  // outlive connections_, since each tunnel unlinks from it in Close().
  QuictunIdleTracker idle_tracker_;

  // Keyed by connection ID, the way QuicDispatcher's own session_map_ is,
  // and necessarily so: every connection now shares the one listen socket,
  // and a client that pools several QUIC connections behind a single UDP
  // socket of its own presents all of them from the same peer address.
  absl::flat_hash_map<QuicConnectionId,
                      std::unique_ptr<QuictunServerConnection>,
                      QuicConnectionIdHash>
      connections_;
  std::vector<QuicConnectionId> pending_removal_;

  // Per-event-loop-iteration budget for how many brand-new connections
  // ProcessPacket() may create -- see max_new_connections_per_event_loop_
  // above. Reset to that value by CollectGarbage()
  // (called once per iteration, right after the packets that iteration's
  // RunEventLoopOnce() delivered have all been processed -- see quictun_
  // server_bin.cc's main loop), decremented once per connection actually
  // created, checked (and, if exhausted, left at zero without going
  // negative) before ProcessPacket() creates another.
  int32_t new_connections_allowed_this_event_loop_ = 0;
};

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_SERVER_DRIVER_H_
