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
#include "quiche/quic/core/crypto/quic_compressed_certs_cache.h"
#include "quiche/quic/core/crypto/quic_crypto_server_config.h"
#include "quiche/quic/core/deterministic_connection_id_generator.h"
#include "quiche/quic/core/io/event_loop_socket_factory.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_default_connection_helper.h"
#include "quiche/quic/core/quic_packet_reader.h"
#include "quiche/quic/core/quic_process_packet_interface.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/quictun_flags.h"
#include "quiche/quic/tools/quictun_server_connection.h"

namespace quic {

// Owns the rendezvous UDP socket on --listen. On the first datagram from a
// never-seen peer, migrates it to its own dedicated, connected UDP socket
// (see quictun_server_connection.cc / quictun_socket_util.h) and constructs
// a QuictunServerConnection for it -- no QuicDispatcher, no shared socket,
// no per-connection demuxing by connection ID. Also owns the state shared
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
                      const QuictunTuningOptions& options);

  // Creates, binds, and registers the rendezvous UDP socket. Returns
  // non-ok on failure.
  absl::Status Start();

  // QuicSocketEventListener (for the rendezvous UDP socket):
  void OnSocketEvent(QuicEventLoop* event_loop, SocketFd fd,
                     QuicSocketEventMask events) override;

  // ProcessPacketInterface (for the rendezvous UDP socket):
  void ProcessPacket(const QuicSocketAddress& self_address,
                     const QuicSocketAddress& peer_address,
                     const QuicReceivedPacket& packet) override;

  // See QuictunClientDriver::CollectGarbage() -- identical rationale:
  // QuictunServerConnection::Close() can't safely destroy itself
  // synchronously from within its own callback stack.
  void CollectGarbage();

 private:
  void RemoveConnection(QuictunServerConnection* connection);

  QuicEventLoop* const event_loop_;
  const QuicSocketAddress listen_address_;
  const std::optional<QuicSocketAddress> target_address_;
  const QuictunTuningOptions options_;

  OwnedSocketFd rendezvous_fd_;
  QuicPacketReader reader_;

  QuicDefaultConnectionHelper helper_;
  std::unique_ptr<QuicAlarmFactory> alarm_factory_;
  DeterministicConnectionIdGenerator connection_id_generator_;
  QuicConfig config_template_;
  std::unique_ptr<QuicCryptoServerConfig> crypto_config_;
  QuicCompressedCertsCache compressed_certs_cache_;
  EventLoopSocketFactory socket_factory_;
  CongestionControlType congestion_control_;

  // Keyed by peer address so a peer's retransmitted/coalesced first packets
  // that are still in flight (already queued on the rendezvous socket
  // before the kernel finishes routing that peer to its new dedicated
  // socket -- see quictun_server_connection.cc) get delivered to the
  // connection already created for them instead of spawning a duplicate.
  absl::flat_hash_map<QuicSocketAddress, std::unique_ptr<QuictunServerConnection>,
                      QuicSocketAddressHash>
      connections_;
  std::vector<QuicSocketAddress> pending_removal_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_SERVER_DRIVER_H_
