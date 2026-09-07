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
#include "quiche/quic/core/quic_blocked_writer_list.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_packet_reader.h"
#include "quiche/quic/core/quic_packet_writer.h"
#include "quiche/quic/core/quic_process_packet_interface.h"
#include "quiche/quic/tools/quictun_client_connection.h"
#include "quiche/quic/tools/quictun_flags.h"
#include "quiche/common/quiche_buffer_allocator.h"

namespace quic {

// Owns the --local TCP listener and the --udp_socket local UDP sockets;
// for each accepted TCP connection, assigns it as one more stream on one of
// the --udp_socket x --conn_per_udp QUIC connections, building that
// connection first if its slot is empty or dead -- see
// AcceptLoop()/pool_slots_. Owns the state shared
// by every connection: the crypto config (with PSK and, if 0-RTT is
// enabled, a session cache shared across all connections made to the same
// --remote within this process's lifetime), the connection helper/alarm
// factory/connection-ID generator, and the QuicConfig template.
class QUICHE_EXPORT QuictunClientDriver : public QuicSocketEventListener,
                                          public ProcessPacketInterface {
 public:
  QuictunClientDriver(QuicEventLoop* event_loop,
                      const QuicSocketAddress& local_address,
                      const QuicSocketAddress& remote_address,
                      const QuictunTuningOptions& options);

  // Creates and binds/listens the --local TCP socket. Returns non-ok on
  // failure.
  absl::Status Start();

  // QuicSocketEventListener (for the --local TCP listen socket):
  // ProcessPacketInterface (for the UDP sockets): routes by the
  // destination connection ID, the only demultiplexing key a 1-RTT short
  // header carries -- which socket a packet arrived on is not consulted,
  // since the ID alone identifies the connection.
  void ProcessPacket(const QuicSocketAddress& self_address,
                     const QuicSocketAddress& peer_address,
                     const QuicReceivedPacket& packet) override;

  void OnSocketEvent(QuicEventLoop* event_loop, SocketFd fd,
                     QuicSocketEventMask events) override;

  // Destroys any connections that closed themselves during the current
  // event-loop iteration. Must be called once per iteration, from outside
  // any QuictunClientConnection callback (see quictun_client_bin.cc) -- see
  // the comment on pending_removal_ for why this can't happen synchronously
  // from within a connection's own close path.
  // Called by a connection whose write hit its socket's full send buffer;
  // drained in OnSocketEvent() when that socket reports writable again.
  // Which socket that is comes from the connection's own creation site
  // (CreateNewConnection() binds it into the callback), since a connection
  // is pinned to one socket for its whole life.
  void OnWriteBlocked(QuicBlockedWriterInterface* blocked_writer,
                      size_t socket_index);

  void CollectGarbage();

  // Closes every tunnel that has gone quiet for --tcp_idle_timeout_seconds.
  // Called once per event-loop iteration alongside CollectGarbage(), and
  // for the same reason it lives there rather than in an alarm: closing a
  // tunnel reenters its owner, so it has to happen at a point where no
  // tunnel's or connection's own call stack is still unwinding. Costs one
  // comparison when nothing has expired -- see QuictunIdleTracker.
  void CloseIdleTunnels();


 private:
  void AcceptLoop();
  void RemoveConnection(QuictunClientConnection* connection,
                        size_t socket_index);

  // Creates a brand-new QuictunClientConnection over udp_sockets_[socket],
  // taking (shared) ownership via connections_ and returning a second
  // reference to it for AcceptLoop() to drop a weak_ptr to into the
  // freshly-(re)claimed pool_slots_ entry. See pool_slots_'s own comment
  // for why shared_ptr, not a raw pointer.
  std::shared_ptr<QuictunClientConnection> CreateNewConnection(
      size_t socket_index);

  // One local UDP socket: its own source port -- which is the whole point
  // of there being more than one, see --udp_socket -- plus the writer every
  // connection pinned to it borrows, and the list of those connections
  // currently blocked on its send buffer.
  struct UdpSocket {
    OwnedSocketFd fd;
    QuicSocketAddress self_address;
    std::unique_ptr<QuicPacketWriter> writer;
    // Same role as QuicDispatcher::write_blocked_list_: several connections
    // share this socket, so there is no per-connection writability event
    // any more and a full send buffer would otherwise wedge the process.
    QuicBlockedWriterList write_blocked_list;
  };

  // Which socket an event is for. A linear scan over --udp_socket
  // entries, which is a handful at most.
  UdpSocket* FindUdpSocketByFd(SocketFd fd);

  QuicEventLoop* const event_loop_;
  const QuicSocketAddress local_address_;
  const QuicSocketAddress remote_address_;
  const QuictunTuningOptions options_;

  OwnedSocketFd listen_fd_;

  // --udp_socket entries, all connected to remote_address_ so reads need
  // no per-packet address handling. unique_ptr so an entry's address is
  // fixed for its whole life: connections and blocked-writer lists are
  // reached through it long after Start() built the vector.
  std::vector<std::unique_ptr<UdpSocket>> udp_sockets_;
  // --udp_socket, clamped to at least 1 in the constructor. Equal to
  // udp_sockets_.size() once Start() has succeeded, but needed before
  // that to size pool_slots_.
  size_t udp_socket_count_ = 1;
  // Shared across every socket: ReadAndDispatchPackets() takes the fd as
  // an argument and the read buffers are pure scratch, so one reader
  // serves them all rather than each carrying its own ~31 KB.
  QuicPacketReader udp_reader_;
  // Keyed by the client connection ID each connection was given at
  // construction; ProcessPacket() looks packets up here.
  absl::flat_hash_map<QuicConnectionId, QuictunClientConnection*,
                      QuicConnectionIdHash>
      by_cid_;
  uint64_t next_client_cid_ = 1;

  QuicDefaultConnectionHelper helper_;
  std::unique_ptr<QuicAlarmFactory> alarm_factory_;
  DeterministicConnectionIdGenerator connection_id_generator_;
  QuicConfig config_template_;
  QuicServerId server_id_;
  std::unique_ptr<QuicCryptoClientConfig> crypto_config_;
  quiche::QuicheBufferAllocator* const buffer_allocator_;
  CongestionControlType congestion_control_;

  // Every live tunnel across every connection this driver owns. Must
  // outlive connections_, since each tunnel unlinks from it in Close().
  QuictunIdleTracker idle_tracker_;

  absl::flat_hash_map<QuictunClientConnection*,
                      std::shared_ptr<QuictunClientConnection>>
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

  // The connection pool: a fixed-size (== --udp_socket x --conn_per_udp)
  // array of slots, each either empty/expired or referencing one of this
  // driver's own connections_ entries. weak_ptr, not a raw pointer --
  // modeled on real QUICHE's own QuicDispatcher, which faces the identical
  // problem (something needs a non-owning reference to a session whose
  // actual destruction is deliberately deferred past the moment it's
  // logically "closed") and solves it by making the canonical owner
  // (reference_counted_session_map_) hold shared_ptr<QuicSession> so any
  // other reference can safely be weak_ptr instead of a raw pointer that
  // has to be manually invalidated by every single place that might hold
  // one. A previous version of this pool used raw QuictunClientConnection*
  // slots RemoveConnection() had to remember to null out synchronously
  // before CollectGarbage() could free the connection -- easy to add a new
  // non-owning reference elsewhere later and forget to wire it into that
  // same invalidation step (that's exactly how the raw-pointer version's
  // real, reproduced-under-ASan use-after-free happened). lock() makes
  // that whole class of bug structurally impossible: a slot whose
  // connection has actually been destroyed just resolves to nullptr, same
  // as an empty slot, with zero bookkeeping required anywhere else.
  //
  // Modeled on kcptun's own --conn pool (github.com/xtaci/kcptun,
  // client/main.go) for the fixed-slots + check-and-lazily-replace part:
  // round-robin blindly picks a slot, and only that slot's own current
  // state (empty/expired vs. alive) at the moment it's picked determines
  // whether to reuse it or build a new connection -- no separate "which
  // slots are still alive" set kept eagerly in sync with every close.
  // AcceptLoop() is the only reader/writer, always from the same
  // single-threaded event loop, so there's no locking here, matching
  // kcptun's own single-goroutine accept loop for the same reason.
  //
  // Slot i lives on udp_sockets_[i % --udp_socket], so round-robining
  // straight through this array visits every socket before returning to
  // any of them -- with --conn_per_udp=1 consecutive TCP connections
  // strictly alternate sockets, which is what makes --udp_socket=K
  // actually present K source ports to a per-5-tuple policer rather than
  // filling the first socket first.
  std::vector<std::weak_ptr<QuictunClientConnection>> pool_slots_;
  size_t pool_round_robin_next_ = 0;
};

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_CLIENT_DRIVER_H_
