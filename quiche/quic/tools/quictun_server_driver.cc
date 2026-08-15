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

// Mirrors QuicDispatcher::kMinClientInitialPacketLength (quic_dispatcher.cc)
// -- see its use in ProcessPacket() for the full rationale.
constexpr QuicByteCount kQuictunMinInitialPacketLength = 1200;

}  // namespace

QuictunServerDriver::QuictunServerDriver(QuicEventLoop* event_loop,
                                         const QuicSocketAddress& listen_address,
                                         std::optional<QuicSocketAddress> target_address,
                                         const QuictunTuningOptions& options,
                                         int32_t max_new_connections_per_event_loop,
                                         int32_t max_concurrent_connections)
    : event_loop_(event_loop),
      listen_address_(listen_address),
      target_address_(target_address),
      options_(options),
      max_new_connections_per_event_loop_(max_new_connections_per_event_loop),
      max_concurrent_connections_(max_concurrent_connections),
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
  // See --max_streams_per_connection's own comment (quictun_flags.h) --
  // in practice this is the value that actually matters (quictun's
  // streams are always client-initiated, so it's what the SERVER
  // advertises as its own incoming limit that gates the CLIENT's
  // concurrently-open stream count).
  config_template_.SetMaxBidirectionalStreamsToSend(
      options.max_streams_per_connection);

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

  // Seeded here, not left at its member-declaration default (0): the very
  // first RunEventLoopOnce() call, before CollectGarbage() has ever run
  // once to reset this for real, would otherwise see a zero budget and
  // drop every connection attempt in that first iteration.
  new_connections_allowed_this_event_loop_ = max_new_connections_per_event_loop_;
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
            << ", tunneling to "
            << (target_address_.has_value()
                    ? target_address_->ToString()
                    : std::string("(transparent mode)"))
            << std::endl;
  return absl::OkStatus();
}

void QuictunServerDriver::OnSocketEvent(QuicEventLoop* /*event_loop*/,
                                        SocketFd /*fd*/,
                                        QuicSocketEventMask events) {
  if (events & kSocketEventReadable) {
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

  // Everything from here on is about to create a brand-new connection --
  // the existing-connection fast path above already returned if this
  // packet belonged to one. Three cheap admission checks, cheapest first,
  // mirroring real QUICHE's own QuicDispatcher layered defense
  // (MaybeDispatchPacket()/ProcessChlo() in quic_dispatcher.cc) against a
  // flood of packets that merely parse as plausible first packets:
  if (packet.length() < kQuictunMinInitialPacketLength) {
    // Mirrors QuicDispatcher's own kMinClientInitialPacketLength (1200,
    // quic_dispatcher.cc) -- RFC 9000 section 14.1 requires a real client
    // to pad its actual Initial packet's UDP datagram to at least this
    // size, precisely so a server can cheaply reject anything smaller as
    // definitely not a genuine handshake attempt without parsing a single
    // byte of it. quictun_client's own Initial packets already satisfy
    // this for free -- they're real QuicConnection/QuicPacketCreator
    // output, which pads crypto/CHLO packets the same way any compliant
    // QUIC client does (see QuicPacketCreator::ConsumeCryptoData()'s
    // needs_full_padding handling) -- so this only ever rejects packets
    // no real quictun_client would ever send.
    QUIC_LOG(INFO) << "Dropping undersized first packet from " << peer_address
                  << ": " << packet.length() << " bytes";
    return;
  }
  if (connections_.size() >=
      static_cast<size_t>(max_concurrent_connections_)) {
    // See --max_concurrent_connections's own comment (quictun_server_bin.cc).
    QUIC_LOG(INFO) << "Dropping new connection attempt from " << peer_address
                  << ": at max_concurrent_connections ("
                  << max_concurrent_connections_
                  << "), current connections_.size()=" << connections_.size();
    return;
  }
  if (new_connections_allowed_this_event_loop_ <= 0) {
    // See new_connections_allowed_this_event_loop_'s own comment
    // (quictun_server_driver.h) -- a real client's own QUIC handshake
    // retransmission logic retries on its own, so dropping here just
    // spreads a burst of genuine connection attempts across a couple of
    // event-loop ticks instead of creating them all in this one.
    QUIC_LOG(INFO) << "Dropping new connection attempt from " << peer_address
                  << ": max_new_connections_per_event_loop budget exhausted "
                     "for this tick";
    return;
  }

  std::unique_ptr<QuictunServerConnection> connection =
      QuictunServerConnection::Create(
          event_loop_, &helper_, alarm_factory_.get(), &socket_factory_,
          connection_id_generator_, config_template_, crypto_config_.get(),
          &compressed_certs_cache_, listen_address_, self_address, peer_address,
          target_address_, options_.transparent,
          QuicConnectionId(destination_connection_id),
          options_.psk, congestion_control_, options_.so_txtime,
          options_.udp_socket_buffer_bytes, packet,
          [this](QuictunServerConnection* c) { RemoveConnection(c); });
  if (connection == nullptr) {
    return;
  }
  SetQuictunStartupBandwidthHint(connection->connection(),
                                 options_.startup_bandwidth_kbps,
                                 options_.startup_rtt_ms);
  connections_.emplace(peer_address, std::move(connection));
  --new_connections_allowed_this_event_loop_;
}

void QuictunServerDriver::RemoveConnection(QuictunServerConnection* connection) {
  pending_removal_.push_back(connection->peer_address());
}

void QuictunServerDriver::CollectGarbage() {
  // Per-stream cleanup no longer needs anything from here: each
  // QuictunServerConnection now drives its own stream_garbage_alarm_ (see
  // its class comment), mirroring how real QUICHE's QuicSession cleans up
  // closed_streams_ via its own alarm rather than something external
  // polling it. This method only ever handled whole-connection removal.
  for (const QuicSocketAddress& peer_address : pending_removal_) {
    connections_.erase(peer_address);
  }
  pending_removal_.clear();

  // Reset the per-tick new-connection budget for the next iteration -- see
  // new_connections_allowed_this_event_loop_'s own comment. Runs right
  // after RunEventLoopOnce() delivered and ProcessPacket()-processed
  // everything for the iteration that just finished, and before the next
  // one delivers anything -- see quictun_server_bin.cc's main loop.
  new_connections_allowed_this_event_loop_ = max_new_connections_per_event_loop_;
}

}  // namespace quic
