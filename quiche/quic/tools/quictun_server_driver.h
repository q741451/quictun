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
#include "quiche/quic/core/quic_packet_reader.h"
#include "quiche/quic/core/quic_process_packet_interface.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/quictun_flags.h"
#include "quiche/quic/tools/quictun_server_connection.h"

namespace quic {

// DoS-resistant replacement for QuicheSocketAddressHash (quiche_socket_
// address.cc) as connections_'s hasher below. QuicheSocketAddressHash is a
// fixed, publicly-known formula (HashIP(host_) ^ (port_ | port_<<16)) with
// no per-process secret -- an attacker who can predict it could craft
// (IP,port) pairs that all land in the same bucket, degrading connections_
// lookups from O(1) toward O(n) per packet on quictun's single event-loop
// thread. Mirrors real QUICHE's own QuicConnectionIdHash (quic_connection_
// id.h/.cc) exactly: SipHash-2-4 keyed with a key generated once per
// process (function-local static -- same Meyer's-singleton pattern as
// QuicConnectionId::Hash(), guaranteed to run its initializer exactly once
// even if operator() is first called concurrently... though nothing here
// actually is concurrent, quictun being single-threaded).
class QuictunPeerAddressHash {
 public:
  size_t operator()(const QuicSocketAddress& address) const noexcept {
    static const SipHashKey key = GenerateKey();
    std::string packed = address.host().ToPackedString();
    uint16_t port = address.port();
    packed.push_back(static_cast<char>((port >> 8) & 0xff));
    packed.push_back(static_cast<char>(port & 0xff));
    return static_cast<size_t>(SIPHASH_24(
        key.data, reinterpret_cast<const uint8_t*>(packed.data()),
        packed.size()));
  }

 private:
  struct SipHashKey {
    uint64_t data[2];
  };
  static SipHashKey GenerateKey() {
    SipHashKey key;
    QuicRandom::GetInstance()->RandBytes(&key.data, sizeof(key.data));
    return key;
  }
};

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
                      const QuictunTuningOptions& options,
                      int32_t max_new_connections_per_event_loop,
                      int32_t max_concurrent_connections);

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
  // synchronously from within its own callback stack. Also resets
  // new_connections_allowed_this_event_loop_ for the next iteration --
  // see that member's comment.
  void CollectGarbage();

 private:
  void RemoveConnection(QuictunServerConnection* connection);

  QuicEventLoop* const event_loop_;
  const QuicSocketAddress listen_address_;
  const std::optional<QuicSocketAddress> target_address_;
  const QuictunTuningOptions options_;
  const int32_t max_new_connections_per_event_loop_;
  const int32_t max_concurrent_connections_;

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
                      QuictunPeerAddressHash>
      connections_;
  std::vector<QuicSocketAddress> pending_removal_;

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
