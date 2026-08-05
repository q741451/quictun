// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_TOOLS_QUICTUN_CLIENT_DRIVER_H_
#define QUICHE_QUIC_TOOLS_QUICTUN_CLIENT_DRIVER_H_

#include <memory>
#include <vector>

#include "absl/status/status.h"
#include "absl/container/flat_hash_map.h"
#include "quiche/quic/core/crypto/quic_client_session_cache.h"
#include "quiche/quic/core/crypto/quic_crypto_client_config.h"
#include "quiche/quic/core/deterministic_connection_id_generator.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_default_connection_helper.h"
#include "quiche/quic/core/quic_server_id.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/quictun_client_connection.h"
#include "quiche/quic/tools/quictun_flags.h"
#include "quiche/common/quiche_buffer_allocator.h"

namespace quic {

// Owns the --local TCP listener; for each accepted connection, builds a new
// QuictunClientConnection (its own dedicated UDP socket + QUIC connection).
// Owns the state shared by every such connection: the crypto config (with
// PSK and, if 0-RTT is enabled, a session cache shared across all
// connections made to the same --remote within this process's lifetime),
// the connection helper/alarm factory/connection-ID generator, and the
// QuicConfig template.
class QUICHE_EXPORT QuictunClientDriver : public QuicSocketEventListener {
 public:
  QuictunClientDriver(QuicEventLoop* event_loop,
                      const QuicSocketAddress& local_address,
                      const QuicSocketAddress& remote_address,
                      const QuictunTuningOptions& options);

  // Creates and binds/listens the --local TCP socket. Returns non-ok on
  // failure.
  absl::Status Start();

  // QuicSocketEventListener (for the --local TCP listen socket):
  void OnSocketEvent(QuicEventLoop* event_loop, SocketFd fd,
                     QuicSocketEventMask events) override;

  // Destroys any connections that closed themselves during the current
  // event-loop iteration. Must be called once per iteration, from outside
  // any QuictunClientConnection callback (see quictun_client_bin.cc) -- see
  // the comment on pending_removal_ for why this can't happen synchronously
  // from within a connection's own close path.
  void CollectGarbage();

 private:
  void AcceptLoop();
  void RemoveConnection(QuictunClientConnection* connection);

  QuicEventLoop* const event_loop_;
  const QuicSocketAddress local_address_;
  const QuicSocketAddress remote_address_;
  const QuictunTuningOptions options_;

  OwnedSocketFd listen_fd_;

  QuicDefaultConnectionHelper helper_;
  std::unique_ptr<QuicAlarmFactory> alarm_factory_;
  DeterministicConnectionIdGenerator connection_id_generator_;
  QuicConfig config_template_;
  QuicServerId server_id_;
  std::unique_ptr<QuicCryptoClientConfig> crypto_config_;
  quiche::QuicheBufferAllocator* const buffer_allocator_;
  CongestionControlType congestion_control_;

  absl::flat_hash_map<QuictunClientConnection*,
                      std::unique_ptr<QuictunClientConnection>>
      connections_;
  // Populated by RemoveConnection() (invoked via a QuictunClientConnection's
  // on_closed callback, which fires from deep within that connection's own
  // socket-event callback stack) and drained by CollectGarbage(). Destroying
  // a QuictunClientConnection synchronously from within that same callback
  // stack would destroy objects (the QuicConnection, the TCP socket, the
  // QuictunTunnel) whose own member functions are still executing higher up
  // the stack -- so actual destruction is deferred until CollectGarbage()
  // runs at the top level, between event-loop iterations.
  std::vector<QuictunClientConnection*> pending_removal_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_CLIENT_DRIVER_H_
