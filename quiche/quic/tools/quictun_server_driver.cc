// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_server_driver.h"

#include <algorithm>
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
  absl::StatusOr<OwnedSocketFd> fd = CreateListenUdpSocket(
      listen_address_, options_.udp_socket_buffer_bytes);
  if (!fd.ok()) {
    return fd.status();
  }
  listen_fd_ = *std::move(fd);

  absl::Status status = socket_api::Bind(*listen_fd_, listen_address_);
  if (!status.ok()) {
    return status;
  }

  // One writer over the one listen socket, shared by every connection --
  // see QuictunServerConnection's ctor. Created here rather than per
  // connection so its GSO batch buffer (64 KiB) and the socket's own
  // kernel buffers exist once per process instead of once per peer.
  shared_writer_ = MakeQuictunPacketWriter(*listen_fd_, options_.so_txtime,
                                           event_loop_);

  bool registered = event_loop_->RegisterSocket(
      *listen_fd_,
      kSocketEventReadable | kSocketEventWritable | kSocketEventError, this);
  if (!registered) {
    return absl::InternalError("Failed to register listen UDP socket");
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
  if (events & kSocketEventError) {
    // Consume it (an ICMP unreachable, typically) so the level-triggered
    // loop does not spin on an unread POLLERR, but do not act on it: it is
    // trivially spoofable and, on a socket shared by every connection, not
    // attributable to any one of them anyway.
    absl::Status error = socket_api::GetSocketError(*listen_fd_);
    if (!error.ok()) {
      QUIC_LOG_EVERY_N_SEC(INFO, 10)
          << "quictun listen socket reported an error (consumed): " << error;
    }
    if (!event_loop_->SupportsEdgeTriggered()) {
      event_loop_->RearmSocket(*listen_fd_, kSocketEventError);
    }
  }
  if (events & kSocketEventWritable) {
    // Mirrors QuicDispatcher::OnCanWrite(): the one shared writer is
    // writable again, so clear its blocked flag and let every connection
    // that was waiting on it retry.
    shared_writer_->SetWritable();
    write_blocked_list_.OnWriterUnblocked();
    if (!write_blocked_list_.Empty() && !event_loop_->SupportsEdgeTriggered()) {
      event_loop_->RearmSocket(*listen_fd_, kSocketEventWritable);
    }
  }
  if (events & kSocketEventReadable) {
    bool more_to_read = true;
    while (more_to_read) {
      more_to_read = reader_.ReadAndDispatchPackets(
          *listen_fd_, listen_address_.port(), *event_loop_->GetClock(), this,
          // Nothing to pass: QuicPacketReader ignores this parameter
          // outright, whatever its header still claims. Kernel receive-buffer
          // drops show up in /proc/net/snmp's UdpRcvbufErrors instead.
          /*packets_dropped=*/nullptr);
    }
    if (!event_loop_->SupportsEdgeTriggered()) {
      event_loop_->RearmSocket(*listen_fd_, kSocketEventReadable);
    }
  }
}

void QuictunServerDriver::OnWriteBlocked(
    QuicBlockedWriterInterface* blocked_writer) {
  write_blocked_list_.Add(*blocked_writer);
  if (!event_loop_->SupportsEdgeTriggered()) {
    event_loop_->RearmSocket(*listen_fd_, kSocketEventWritable);
  }
}

void QuictunServerDriver::ProcessPacket(const QuicSocketAddress& self_address,
                                        const QuicSocketAddress& peer_address,
                                        const QuicReceivedPacket& packet) {
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

  if (header_error != QUIC_NO_ERROR) {
    QUIC_DVLOG(1) << "Dropping unparseable packet from " << peer_address << ": "
                  << detailed_error;
    return;
  }
  const QuicConnectionId dcid(destination_connection_id);

  auto existing = connections_.find(dcid);
  if (existing != connections_.end()) {
    existing->second->ProcessPacket(self_address, peer_address, packet);
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
          shared_writer_.get(), &idle_tracker_,
          [this](QuicBlockedWriterInterface* w) { OnWriteBlocked(w); }, packet,
          [this](QuictunServerConnection* c) { RemoveConnection(c); });
  if (connection == nullptr) {
    return;
  }
  SetQuictunStartupBandwidthHint(connection->connection(),
                                 options_.startup_bandwidth_kbps,
                                 options_.startup_rtt_ms);
  connections_.emplace(dcid, std::move(connection));
  --new_connections_allowed_this_event_loop_;
}

void QuictunServerDriver::RemoveConnection(QuictunServerConnection* connection) {
  // See QuictunClientDriver::RemoveConnection() -- same reason, same fix.
  write_blocked_list_.Remove(*connection->connection());
  pending_removal_.push_back(connection->connection_id());
}

void QuictunServerDriver::CollectGarbage() {
  // Per-stream cleanup no longer needs anything from here: each
  // QuictunServerConnection now drives its own stream_garbage_alarm_ (see
  // its class comment), mirroring how real QUICHE's QuicSession cleans up
  // closed_streams_ via its own alarm rather than something external
  // polling it. This method only ever handled whole-connection removal.
  for (const QuicConnectionId& id : pending_removal_) {
    // Second half of QuicDispatcher's own pair (CleanUpSession() removes on
    // close, DeleteSessions() asserts nothing is left by destruction): the
    // list holds a raw pointer, so anything still in it here becomes
    // dangling the moment the erase below runs.
    auto it = connections_.find(id);
    if (it == connections_.end()) {
      continue;
    }
    if (write_blocked_list_.Remove(*it->second->connection())) {
      QUIC_BUG(quictun_bug_blocked_writer_at_destruction)
          << "Connection was still in the blocked-writer list at destruction: "
          << id;
    }
    connections_.erase(it);
  }
  pending_removal_.clear();

  // Reset the per-tick new-connection budget for the next iteration -- see
  // new_connections_allowed_this_event_loop_'s own comment. Runs right
  // after RunEventLoopOnce() delivered and ProcessPacket()-processed
  // everything for the iteration that just finished, and before the next
  // one delivers anything -- see quictun_server_bin.cc's main loop.
  new_connections_allowed_this_event_loop_ = max_new_connections_per_event_loop_;
}

void QuictunServerDriver::CloseIdleTunnels() {
  idle_tracker_.CloseIdleTunnels(
      event_loop_->GetClock()->ApproximateNow(), options_.tcp_idle_timeout,
      // A stalled tunnel outliving a merely quiet one is never what an
      // operator meant, so a --tcp_stalled_timeout_seconds above
      // --tcp_idle_timeout_seconds is read as "no separate stalled class".
      std::min(options_.tcp_stalled_timeout, options_.tcp_idle_timeout));
}

}  // namespace quic
