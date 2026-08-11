// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_server_connection.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_framer.h"
#include "quiche/quic/core/quic_packet_writer.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/tools/quictun_connection_factory.h"
#include "quiche/quic/tools/quictun_socket_util.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace quic {

namespace {

// Fires stream_garbage_alarm_ -- see that member's comment. Mirrors
// DeleteSessionsAlarm in quic_dispatcher.cc exactly, one level down
// (per-connection stream cleanup instead of per-dispatcher session
// cleanup).
class StreamGarbageAlarmDelegate : public QuicAlarm::DelegateWithoutContext {
 public:
  explicit StreamGarbageAlarmDelegate(QuictunServerConnection* connection)
      : connection_(connection) {}
  StreamGarbageAlarmDelegate(const StreamGarbageAlarmDelegate&) = delete;
  StreamGarbageAlarmDelegate& operator=(const StreamGarbageAlarmDelegate&) =
      delete;

  void OnAlarm() override { connection_->CollectStreamGarbage(); }

 private:
  QuictunServerConnection* const connection_;
};

}  // namespace

std::unique_ptr<QuictunServerConnection> QuictunServerConnection::Create(
    QuicEventLoop* event_loop, QuicConnectionHelperInterface* helper,
    QuicAlarmFactory* alarm_factory, SocketFactory* socket_factory,
    ConnectionIdGeneratorInterface& connection_id_generator,
    const QuicConfig& config, const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache,
    const QuicSocketAddress& listen_address, const QuicSocketAddress& self_address,
    const QuicSocketAddress& peer_address,
    const QuicSocketAddress& target_address, QuicConnectionId server_connection_id,
    const std::string& psk, CongestionControlType congestion_control,
    bool so_txtime_enabled, QuicByteCount udp_socket_buffer_bytes,
    const QuicReceivedPacket& first_packet,
    std::function<void(QuictunServerConnection*)> on_closed) {
  absl::StatusOr<OwnedSocketFd> fd =
      CreateReusableUdpSocket(listen_address, udp_socket_buffer_bytes);
  if (!fd.ok()) {
    QUIC_LOG(ERROR) << "Failed to create per-connection UDP socket for "
                    << peer_address << ": " << fd.status();
    return nullptr;
  }
  OwnedSocketFd udp_fd = *std::move(fd);

  absl::Status bind_status = socket_api::Bind(*udp_fd, listen_address);
  if (!bind_status.ok()) {
    QUIC_LOG(ERROR) << "Failed to bind per-connection UDP socket to "
                    << listen_address << ": " << bind_status;
    return nullptr;
  }

  absl::Status connect_status = socket_api::Connect(*udp_fd, peer_address);
  if (!connect_status.ok()) {
    QUIC_LOG(ERROR) << "Failed to connect per-connection UDP socket to "
                    << peer_address << ": " << connect_status;
    return nullptr;
  }

  return absl::WrapUnique(new QuictunServerConnection(
      event_loop, std::move(udp_fd), self_address, peer_address, helper,
      alarm_factory, socket_factory, connection_id_generator, config,
      crypto_config, compressed_certs_cache, target_address,
      server_connection_id, psk, congestion_control, so_txtime_enabled,
      first_packet, std::move(on_closed)));
}

QuictunServerConnection::QuictunServerConnection(
    QuicEventLoop* event_loop, OwnedSocketFd udp_fd,
    const QuicSocketAddress& self_address, const QuicSocketAddress& peer_address,
    QuicConnectionHelperInterface* helper, QuicAlarmFactory* alarm_factory,
    SocketFactory* socket_factory,
    ConnectionIdGeneratorInterface& connection_id_generator,
    const QuicConfig& config, const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache,
    const QuicSocketAddress& target_address, QuicConnectionId server_connection_id,
    const std::string& psk, CongestionControlType congestion_control,
    bool so_txtime_enabled, const QuicReceivedPacket& first_packet,
    std::function<void(QuictunServerConnection*)> on_closed)
    : event_loop_(event_loop),
      udp_fd_(std::move(udp_fd)),
      self_address_(self_address),
      peer_address_(peer_address),
      target_address_(target_address),
      socket_factory_(socket_factory),
      connection_id_generator_(connection_id_generator),
      expected_psk_(psk),
      idle_timeout_(config.IdleNetworkTimeout()),
      on_closed_(std::move(on_closed)) {
  std::unique_ptr<QuicPacketWriter> writer =
      MakeQuictunPacketWriter(*udp_fd_, so_txtime_enabled, event_loop);

  connection_ = std::make_unique<QuicConnection>(
      server_connection_id, self_address_, peer_address_, helper, alarm_factory,
      writer.release(), /*owns_writer=*/true, Perspective::IS_SERVER,
      GetQuictunVersions(), connection_id_generator);
  SetQuictunCongestionControl(connection_.get(), congestion_control);

  session_ = std::make_unique<QuictunServerSession>(
      connection_.get(), /*owner=*/this, config, "quictun/1", crypto_config,
      compressed_certs_cache);
  // Registered before any packet processing (matching QuictunClientConnection's
  // SetCanOpenStreamCallback/CryptoConnect ordering): guarantees this fires
  // for every incoming stream no matter which of the several packet-delivery
  // paths ends up being the one that actually creates it -- see
  // SetStreamCreatedCallback()'s comment.
  session_->SetStreamCreatedCallback(
      [this](QuicStreamId id) { OnNewStream(id); });
  session_->Initialize();

  // See closed_stream_targets_/stream_garbage_alarm_'s comments -- mirrors
  // QuicSession's own closed_streams_clean_up_alarm_ construction exactly.
  stream_garbage_alarm_.reset(
      alarm_factory->CreateAlarm(new StreamGarbageAlarmDelegate(this)));

  bool registered = event_loop_->RegisterSocket(
      *udp_fd_, kSocketEventReadable | kSocketEventWritable, this);
  QUICHE_DCHECK(registered);

  connection_->ProcessUdpPacket(self_address_, peer_address_, first_packet);
  // Deliberately no --target dial here (unlike the pre-multiplexing
  // version): there is no "the" stream yet to dial for, and each stream
  // that does show up dials independently, once it authenticates -- see
  // StartTunnelForStream(). If processing first_packet already
  // synchronously created and authenticated a stream (only possible if the
  // whole preamble arrived in that first packet, which OnNewStream()
  // already handled via its own synchronous read), that stream already has
  // its own dial-out in flight by the time this constructor returns.
}

QuictunServerConnection::~QuictunServerConnection() {
  event_loop_->UnregisterSocket(*udp_fd_);
}

void QuictunServerConnection::DisconnectStreamTarget(StreamTarget& target) {
  if (target.target_socket && !target.target_socket_disconnected) {
    target.target_socket_disconnected = true;
    target.target_socket->Disconnect();
  }
}

void QuictunServerConnection::Close() {
  if (closed_) {
    return;
  }
  closed_ = true;
  if (connection_->connected()) {
    connection_->CloseConnection(
        QUIC_NO_ERROR, "quictun tunnel closed",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  }
  // Tear every stream's target down directly rather than going through each
  // tunnel's own Close() (which would fire each stream's on_closed callback
  // -- StartTunnelForStream()'s lambda -- reentrantly modifying
  // stream_targets_ while this loop is iterating it): the whole connection
  // is going away regardless, so there's nothing for those callbacks to
  // usefully do here that clearing the map right after doesn't already
  // cover. See DisconnectStreamTarget() for the guard against
  // double-disconnecting a target whose tunnel got as far as SetSocket()
  // (or all the way through its own Close(), if the connection-level close
  // and a stream's own close raced) -- a stream whose dial-out never got
  // that far (still nullptr, see QuictunTunnel::HasSocket()) simply has
  // nothing to disconnect.
  for (auto& [id, target] : stream_targets_) {
    DisconnectStreamTarget(target);
  }
  stream_targets_.clear();
  key_read_buffers_.clear();
  // Same idea as QuicSession::OnConnectionClosed() cancelling its own
  // closed_streams_clean_up_alarm_: whatever's sitting in
  // closed_stream_targets_ is destroyed right here (this whole connection,
  // and everything it owns, is going away regardless), so there's no
  // further need for the alarm to fire and do it again.
  closed_stream_targets_.clear();
  stream_garbage_alarm_->Cancel();
  event_loop_->UnregisterSocket(*udp_fd_);
  std::function<void(QuictunServerConnection*)> on_closed = std::move(on_closed_);
  if (on_closed) {
    on_closed(this);
  }
}

void QuictunServerConnection::CollectStreamGarbage() {
  // See closed_stream_targets_'s comment. This is the actual destruction --
  // of the StreamTarget, and with it the QuictunTunnel and target_socket --
  // now safely outside any tunnel's own call stack (this only ever runs
  // from stream_garbage_alarm_ firing).
  closed_stream_targets_.clear();
}

void QuictunServerConnection::OnConnectionClosed(
    QuicConnectionId /*server_connection_id*/, QuicErrorCode error,
    const std::string& error_details, ConnectionCloseSource source) {
  QUIC_LOG(INFO) << "quictun connection from " << peer_address_
                 << " closed: " << QuicErrorCodeToString(error) << " (\""
                 << error_details << "\"), source="
                 << (source == ConnectionCloseSource::FROM_PEER ? "PEER"
                                                                 : "SELF");
  Close();
}

void QuictunServerConnection::OnSocketEvent(QuicEventLoop* /*event_loop*/,
                                            SocketFd fd,
                                            QuicSocketEventMask events) {
  QUICHE_DCHECK_EQ(fd, *udp_fd_);
  if (events & kSocketEventReadable) {
    bool more_to_read = true;
    while (more_to_read) {
      more_to_read = reader_.ReadAndDispatchPackets(
          *udp_fd_, self_address_.port(), *event_loop_->GetClock(), this,
          /*packets_dropped=*/nullptr);
    }
    if (!event_loop_->SupportsEdgeTriggered()) {
      event_loop_->RearmSocket(*udp_fd_, kSocketEventReadable);
    }
  }
  if (events & kSocketEventWritable) {
    // OnBlockedWriterCanWrite(), not plain OnCanWrite(): this event means
    // "the OS says the socket is writable again", which is specifically
    // what clears the writer's own write_blocked_ bookkeeping first (see
    // QuicConnection::OnBlockedWriterCanWrite() and, for the reference
    // pattern this mirrors, QuicDispatcher::OnCanWrite() in
    // quic_dispatcher.cc). Calling plain OnCanWrite() here instead -- as
    // this used to -- leaves that flag stuck set the first time a real
    // write actually blocks (e.g. the kernel send buffer momentarily
    // full under GSO batching with --so_txtime), so every subsequent
    // firing of this same event hits OnCanWrite()'s own internal
    // QUIC_BUG(quic_bug_10511_22) check and fatally closes the
    // connection instead of recovering -- turning one transient block
    // into a permanently dead connection.
    connection_->OnBlockedWriterCanWrite();
    // `&& connection_->IsWriterBlocked()`, not just `!SupportsEdgeTriggered()`
    // alone: a UDP socket is essentially always writable at the OS level, so
    // on this codebase's only event loop implementation (QuicPollEventLoop,
    // poll()-based, SupportsEdgeTriggered() always false -- there's no epoll
    // variant here), unconditionally re-arming for kSocketEventWritable makes
    // RunEventLoopOnce() return immediately on every single call instead of
    // actually sleeping up to its timeout, pinning one CPU core at 100% for
    // as long as this UDP socket exists -- i.e. for the whole lifetime of any
    // connection. Only re-arm when the writer actually still has something
    // it couldn't send, matching the reference pattern in
    // quic_server_io_harness.cc (`dispatcher_.OnCanWrite(); if (... &&
    // dispatcher_.HasPendingWrites()) { RearmSocket(...); }`).
    if (!event_loop_->SupportsEdgeTriggered() &&
        connection_->IsWriterBlocked()) {
      event_loop_->RearmSocket(*udp_fd_, kSocketEventWritable);
    }
  }
}

void QuictunServerConnection::ProcessPacket(
    const QuicSocketAddress& self_address,
    const QuicSocketAddress& /*peer_address*/, const QuicReceivedPacket& packet) {
  // This dedicated, connect()ed UDP socket can only ever receive packets
  // from peer_address_ -- but that doesn't mean every packet that lands
  // here truly belongs to *this* QUIC connection. Once this connection is
  // torn down server-side (deferred via pending_removal_/CollectGarbage(),
  // see quictun_server_driver.cc), its socket/connect() 4-tuple claim isn't
  // released until the next garbage-collection pass, and UDP source ports
  // have no TCP-style TIME_WAIT delay -- so the client's OS can reuse the
  // exact same ephemeral port for a brand-new connection within
  // milliseconds, and the kernel will keep routing that peer's packets
  // straight to this now-stale socket, bypassing the rendezvous socket (and
  // QuictunServerDriver::ProcessPacket's own same-check) entirely. Forwarding
  // such a packet into a QuicConnection that doesn't recognize its
  // connection ID hits a fatal QUICHE_DCHECK in quic_connection.cc that
  // assumes a server can never see this (an assumption that only holds with
  // a real QuicDispatcher demuxing by connection ID up front, which quictun
  // deliberately doesn't have). Detect and silently drop that case here --
  // the new client's retransmissions will succeed once this connection's
  // socket is actually closed and the 4-tuple frees up, letting them reach
  // the rendezvous socket and be recognized there as a genuinely new
  // connection. Not just Initial packets: once a misrouted new connection's
  // Initial slips through, ITS follow-up Handshake/1-RTT packets would
  // arrive at this same stale socket too (same misrouted 4-tuple) before
  // the client ever hears back -- so every packet's connection ID is
  // checked here, not only long-header Initial ones.
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
  if (header_error == QUIC_NO_ERROR && !destination_connection_id.empty() &&
      QuicConnectionId(destination_connection_id) != connection_->connection_id()) {
    QUIC_LOG(INFO) << "Dropping packet for unrecognized connection ID "
                   << QuicConnectionId(destination_connection_id) << " from "
                   << peer_address_ << " on stale connection "
                   << connection_->connection_id()
                   << "'s socket -- peer reused its address, retry will "
                      "reach the rendezvous socket once this connection is "
                      "garbage-collected";
    return;
  }
  connection_->ProcessUdpPacket(self_address, peer_address_, packet);
}

void QuictunServerConnection::OnNewStream(QuicStreamId id) {
  if (closed_) {
    return;
  }
  key_read_buffers_[id] = "";
  session_->SetStreamDelegate(id, this);
  // The stream may already be holding data (e.g. its whole preamble)
  // buffered by the sequencer from before SetStreamDelegate() attached --
  // SetStreamDelegate() is a plain pointer assignment with no side effects,
  // it does not itself re-deliver an OnDataAvailable()-equivalent
  // notification for already-arrived data. Without this call, that data
  // would simply never be read until (if ever) more data arrives to
  // trigger a fresh OnStreamDataAvailable().
  OnStreamDataAvailable(id);
}

void QuictunServerConnection::OnStreamDataAvailable(QuicStreamId id) {
  auto buffer_it = key_read_buffers_.find(id);
  if (buffer_it == key_read_buffers_.end() || closed_) {
    // Already authenticated (this stream now belongs to a QuictunTunnel,
    // which is its delegate from here on) or the whole connection is on its
    // way down -- either way, nothing for the auth-phase logic to do.
    return;
  }
  std::string& key_read_buffer = buffer_it->second;
  auto stream_it = session_->streams().find(id);
  if (stream_it == session_->streams().end()) {
    // Shouldn't happen (a stream with a key_read_buffers_ entry but no
    // corresponding live stream), but don't crash over it.
    return;
  }
  QuictunStream* stream = stream_it->second;
  char buffer[512];
  bool fin = false;
  bool authenticated = false;
  while (!authenticated) {
    size_t bytes_read = stream->Read(absl::MakeSpan(buffer, sizeof(buffer)), &fin);
    if (bytes_read > 0) {
      key_read_buffer.append(buffer, bytes_read);
    }
    if (key_read_buffer.size() >= 2) {
      size_t key_length = (static_cast<uint8_t>(key_read_buffer[0]) << 8) |
                          static_cast<uint8_t>(key_read_buffer[1]);
      if (key_read_buffer.size() >= 2 + key_length) {
        absl::string_view received_key(key_read_buffer.data() + 2, key_length);
        if (received_key != expected_psk_) {
          // Only this one stream is at fault -- reset it and move on rather
          // than tearing down every other (possibly already-authenticated
          // and actively tunneling) stream sharing this connection. See the
          // class comment.
          QUIC_LOG(WARNING) << "Rejecting stream " << id << " from "
                            << peer_address_ << ": key mismatch";
          stream->Reset(QUIC_BAD_APPLICATION_PAYLOAD);
          key_read_buffers_.erase(id);
          return;
        }
        authenticated = true;
        // Any bytes already read past the preamble are real payload; hand
        // them to the tunnel once it's constructed.
        std::string leftover = key_read_buffer.substr(2 + key_length);
        key_read_buffers_.erase(id);
        StartTunnelForStream(id, stream, std::move(leftover));
        return;
      }
    }
    if (bytes_read == 0) {
      break;
    }
  }
  if (fin && !authenticated) {
    QUIC_LOG(WARNING) << "Stream " << id << " from " << peer_address_
                      << " closed before completing authentication";
    key_read_buffers_.erase(id);
    // Just let the stream's own natural closure run its course (it already
    // has, in fact -- sequencer says fin -- so nothing more to do); no
    // reason to reset it or touch the rest of the connection.
    return;
  }
}

void QuictunServerConnection::StartTunnelForStream(QuicStreamId id,
                                                    QuictunStream* stream,
                                                    std::string leftover) {
  StreamTarget& target = stream_targets_[id];
  // Constructed with no socket yet (see QuictunTunnel::SetSocket()'s
  // comment): this tunnel is about to become the dial-out's AsyncVisitor,
  // so the dial-out can't be created until the tunnel already exists.
  target.tunnel = std::make_unique<QuictunTunnel>(
      stream, /*socket=*/nullptr, idle_timeout_, [this, id] {
        // Mirrors the pre-multiplexing on_closed callback, just scoped to
        // this one stream instead of the whole connection: this stream's
        // tunnel closed itself (any reason -- stream closed, TCP error,
        // idle timeout), so clean up its entry. See
        // QuictunTunnel::HasSocket()'s comment for why this can't just
        // assume the tunnel already disconnected target_socket the way the
        // pre-multiplexing version could.
        //
        // This callback runs from inside QuictunTunnel::Close() -- a member
        // function of the very QuictunTunnel that target.tunnel (a
        // unique_ptr) owns -- which keeps running after this callback
        // returns (see its own comment). So this must NOT synchronously
        // destroy the StreamTarget here: that would destroy the
        // QuictunTunnel object out from under its own still-executing
        // Close(), a real use-after-free (confirmed via direct
        // reproduction). Mirrors QuicSession::PrepareStreamForDestruction()
        // exactly (quic_session.cc): move the StreamTarget out of the live
        // map into closed_stream_targets_ (ownership transferred, object
        // not destroyed yet) and arm stream_garbage_alarm_ to actually
        // destroy it outside this call stack.
        //
        // ClearStreamDelegate() happens in this exact same step, not
        // deferred alongside the real destruction: a second, independent
        // bug (found via a real core dump on real hardware, not just code
        // reading) was that session_->stream_delegates_[id] kept pointing
        // at this StreamTarget's QuictunTunnel after CollectStreamGarbage()
        // destroyed it, with nothing to synchronize the two -- any QUIC
        // frame for this stream id arriving in that window (a late
        // retransmission, the peer still writing) called
        // QuictunSessionBase::OnStreamDataAvailable() straight into freed
        // memory. Clearing the delegate synchronously here, at the same
        // point the StreamTarget leaves the live map, closes that window
        // entirely: from this line on, session_ no longer has any route to
        // this tunnel at all, regardless of when (or whether) the alarm
        // below actually gets to fire.
        auto it = stream_targets_.find(id);
        if (it == stream_targets_.end()) {
          return;
        }
        if (!it->second.tunnel->HasSocket()) {
          DisconnectStreamTarget(it->second);
        } else {
          it->second.target_socket_disconnected = true;
        }
        session_->ClearStreamDelegate(id);
        closed_stream_targets_.push_back(std::move(it->second));
        stream_targets_.erase(it);
        if (!stream_garbage_alarm_->IsSet()) {
          stream_garbage_alarm_->Set(event_loop_->GetClock()->ApproximateNow());
        }
      });
  target.tunnel->SetPendingSeedData(std::move(leftover));

  target.target_socket = socket_factory_->CreateTcpClientSocket(
      target_address_, /*receive_buffer_size=*/0, /*send_buffer_size=*/0,
      target.tunnel.get());
  target.tunnel->SetSocket(target.target_socket.get());
  session_->SetStreamDelegate(id, target.tunnel.get());
  target.target_socket->ConnectAsync();
}

void QuictunServerConnection::OnStreamClosed(QuicStreamId id) {
  // Only relevant during a stream's pre-tunnel auth phase (once a
  // QuictunTunnel exists for it, that tunnel -- not this class -- is the
  // stream's delegate, and handles its own OnStreamClosed()). The stream
  // closing before finishing authentication needs no further action beyond
  // dropping its now-pointless read buffer -- there is no --target
  // dial-out to clean up yet at this stage.
  key_read_buffers_.erase(id);
}

}  // namespace quic
