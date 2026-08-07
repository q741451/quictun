// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_server_driver.h"

#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/crypto_handshake.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_default_clock.h"
#include "quiche/quic/core/quic_framer.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/tools/quictun_certificate.h"
#include "quiche/quic/tools/quictun_connection_factory.h"
#include "quiche/quic/tools/quictun_socket_util.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/simple_buffer_allocator.h"

namespace quic {

namespace {

// QuicPacketReader normalizes v4-mapped IPv6 peer addresses (e.g.
// "::ffff:127.0.0.1") down to plain IPv4 form for its own dispatch
// bookkeeping (see quic_packet_reader.cc's Normalized() call) -- but
// quictun's per-connection sockets are always the same address family as
// the (dual-stack, IPv6) --listen socket, since they must bind to the
// exact same local address for the SO_REUSEADDR/SO_REUSEPORT migration
// trick to work. Handing a plain-IPv4 sockaddr to sendmsg() on an
// AF_INET6-domain socket is a family mismatch the kernel rejects with
// EINVAL, fatally breaking the connection's very first write. Undo the
// normalization by re-mapping back to v4-in-v6 form whenever the listen
// socket is IPv6, matching the socket domain the peer address will
// actually be used with.
QuicSocketAddress AdaptPeerAddressForListenSocket(
    const QuicSocketAddress& listen_address, const QuicSocketAddress& peer_address) {
  if (listen_address.host().address_family() == IpAddressFamily::IP_V6) {
    return QuicSocketAddress(peer_address.host().DualStacked(), peer_address.port());
  }
  return peer_address;
}

// quictun's own authentication is the pre-shared key, which is checked as
// an application-layer preamble on the stream -- this legacy QUIC
// source-address-token secret only guards an older, unrelated
// anti-amplification mechanism, so its exact value doesn't matter; it just
// needs to exist.
constexpr char kSourceAddressTokenSecret[] = "quictun";

}  // namespace

QuictunServerDriver::QuictunServerDriver(QuicEventLoop* event_loop,
                                         const QuicSocketAddress& listen_address,
                                         const QuicSocketAddress& target_address,
                                         const QuictunTuningOptions& options)
    : event_loop_(event_loop),
      listen_address_(listen_address),
      target_address_(target_address),
      options_(options),
      alarm_factory_(event_loop_->CreateAlarmFactory()),
      connection_id_generator_(kQuicDefaultConnectionIdLength),
      compressed_certs_cache_(QuicCompressedCertsCache::kQuicCompressedCertsCacheSize),
      socket_factory_(event_loop_, quiche::SimpleBufferAllocator::Get()),
      congestion_control_(
          ParseQuictunCongestionControl(options.congestion_control)) {
  config_template_.SetIdleNetworkTimeout(options.idle_timeout);
  config_template_.SetInitialStreamFlowControlWindowToSend(
      options.initial_stream_flow_control_window_bytes);
  config_template_.SetInitialSessionFlowControlWindowToSend(
      options.initial_session_flow_control_window_bytes);

  // NOTE: QuicCryptoServerConfig::set_pre_shared_key() is deliberately not
  // called here -- see quictun_client_driver.cc's comment on the client
  // side of this. On the server it's even more unconditional:
  // TlsServerHandshaker::SelectCertificate() QUIC_BUGs (fatally crashing)
  // during *every* incoming handshake's cert selection as soon as the
  // server's own config has a PSK set, regardless of what the client
  // offers. --key is instead checked as an application-layer preamble; see
  // OnStreamDataAvailable() in quictun_server_connection.cc.
  crypto_config_ = std::make_unique<QuicCryptoServerConfig>(
      kSourceAddressTokenSecret, QuicRandom::GetInstance(),
      MakeQuictunSelfSignedProofSource(), KeyExchangeSource::Default(),
      /*proof_verifier=*/nullptr);
  crypto_config_->AddDefaultConfig(QuicRandom::GetInstance(),
                                   QuicDefaultClock::Get(),
                                   QuicCryptoServerConfig::ConfigOptions());

  if (options.so_txtime) {
    EnableQuictunSoTxTime();
  }
}

absl::Status QuictunServerDriver::Start() {
  absl::StatusOr<OwnedSocketFd> fd = CreateReusableUdpSocket(
      listen_address_, options_.udp_socket_buffer_bytes);
  if (!fd.ok()) {
    return fd.status();
  }
  rendezvous_fd_ = *std::move(fd);

  absl::Status status = socket_api::Bind(*rendezvous_fd_, listen_address_);
  if (!status.ok()) {
    return status;
  }

  bool registered = event_loop_->RegisterSocket(
      *rendezvous_fd_, kSocketEventReadable, this);
  if (!registered) {
    return absl::InternalError("Failed to register rendezvous UDP socket");
  }

  // std::cerr, not QUIC_LOG(INFO): see the comment on
  // PrintQuictunStartupBanner() in quictun_flags.cc -- this is the "bind
  // actually succeeded, tunnel is ready" confirmation that completes the
  // startup banner, and needs the same default visibility.
  std::cerr << "quictun_server listening on " << listen_address_
            << ", tunneling to " << target_address_ << std::endl;
  return absl::OkStatus();
}

void QuictunServerDriver::OnSocketEvent(QuicEventLoop* /*event_loop*/,
                                        SocketFd /*fd*/,
                                        QuicSocketEventMask events) {
  if (events & kSocketEventReadable) {
    // Reset once per OnSocketEvent() call, not per packet -- see the
    // member's own comment in the header.
    new_connection_budget_ = kMaxNewConnectionsPerSocketEvent;
    bool more_to_read = true;
    while (more_to_read) {
      more_to_read = reader_.ReadAndDispatchPackets(
          *rendezvous_fd_, listen_address_.port(), *event_loop_->GetClock(),
          this, /*packets_dropped=*/nullptr);
    }
    if (!event_loop_->SupportsEdgeTriggered()) {
      event_loop_->RearmSocket(*rendezvous_fd_, kSocketEventReadable);
    }
  }
}

void QuictunServerDriver::ProcessPacket(const QuicSocketAddress& self_address,
                                        const QuicSocketAddress& raw_peer_address,
                                        const QuicReceivedPacket& packet) {
  const QuicSocketAddress peer_address =
      AdaptPeerAddressForListenSocket(listen_address_, raw_peer_address);

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

  auto existing = connections_.find(peer_address);
  if (existing != connections_.end()) {
    // Normally this is just a packet from a peer already migrated to its
    // own socket, still queued on the rendezvous socket from before the
    // kernel finished routing them there -- see the header comment on
    // connections_. But it can also be an Initial packet for a genuinely
    // NEW connection that happens to reuse the exact same (peer IP,
    // ephemeral port) as an old one we haven't garbage-collected yet: UDP
    // source ports have no TIME_WAIT-style reuse delay the way TCP ports
    // do, so a client can reuse a port within milliseconds of its previous
    // connection closing. Blindly forwarding that new Initial into the
    // stale QuicConnection hits a fatal QUICHE_DCHECK in
    // quic_connection.cc's connection-ID validation, which assumes a
    // server never sees a mismatched connection ID directly -- an
    // assumption that only holds with a real QuicDispatcher doing
    // connection-ID-based demuxing up front, which quictun deliberately
    // doesn't have (see the architecture comment in this file). Detect
    // that case and replace the stale entry instead of forwarding to it.
    bool looks_like_new_connection =
        header_error == QUIC_NO_ERROR && version_present &&
        long_packet_type == INITIAL &&
        QuicConnectionId(destination_connection_id) !=
            existing->second->connection_id();
    if (!looks_like_new_connection) {
      existing->second->ProcessPacket(self_address, peer_address, packet);
      return;
    }
    QUIC_LOG(INFO) << "Peer " << peer_address
                   << " reused its address for a new connection (old "
                      "connection ID "
                   << existing->second->connection_id() << ", new "
                   << QuicConnectionId(destination_connection_id)
                   << ") -- replacing the stale entry";
    connections_.erase(existing);
  }

  if (header_error != QUIC_NO_ERROR) {
    QUIC_DVLOG(1) << "Dropping unparseable first packet from " << peer_address
                 << ": " << detailed_error;
    return;
  }

  if (new_connection_budget_ <= 0) {
    // This event-loop pass has already created kMaxNewConnectionsPerSocketEvent
    // connections -- don't act on this packet now (see the member's own
    // comment in the header for why: bound how much of one pass a burst of
    // new connections can monopolize). Not buffered for explicit redelivery;
    // the peer's own QUIC retransmission of this unacknowledged Initial
    // packet will arrive again on a later iteration, once budget resets.
    QUIC_DVLOG(1) << "Deferring new connection from " << peer_address
                 << ": per-event-loop-pass new connection budget exhausted";
    return;
  }

  std::unique_ptr<QuictunServerConnection> connection =
      QuictunServerConnection::Create(
          event_loop_, &helper_, alarm_factory_.get(), &socket_factory_,
          connection_id_generator_, config_template_, crypto_config_.get(),
          &compressed_certs_cache_, listen_address_, self_address, peer_address,
          target_address_, QuicConnectionId(destination_connection_id),
          options_.psk, congestion_control_, options_.so_txtime,
          options_.udp_socket_buffer_bytes, packet,
          [this](QuictunServerConnection* c) { RemoveConnection(c); });
  if (connection == nullptr) {
    return;
  }
  --new_connection_budget_;
  SetQuictunStartupBandwidthHint(connection->connection(),
                                 options_.startup_bandwidth_kbps,
                                 options_.startup_rtt_ms);
  connections_.emplace(peer_address, std::move(connection));
}

void QuictunServerDriver::RemoveConnection(QuictunServerConnection* connection) {
  pending_removal_.push_back(connection->peer_address());
}

void QuictunServerDriver::CollectGarbage() {
  for (const QuicSocketAddress& peer_address : pending_removal_) {
    connections_.erase(peer_address);
  }
  pending_removal_.clear();
}

}  // namespace quic
