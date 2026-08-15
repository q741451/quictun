// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_server_connection.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

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

// Result of trying to parse a --transparent address header (ss-server-style
// ATYP+addr+port, IPv4/IPv6 only -- no domain-name ATYP, since a
// transparent proxy only ever captures a concrete IP off SO_ORIGINAL_DST,
// never a hostname) out of whatever's been buffered so far.
enum class TransparentHeaderParseResult {
  kIncomplete,  // Need more bytes; buffer holds a valid-so-far prefix.
  kInvalid,     // Bad ATYP or corrupt bytes -- reject the stream outright.
  kComplete,
};

struct ParsedTransparentHeader {
  TransparentHeaderParseResult result = TransparentHeaderParseResult::kIncomplete;
  size_t header_length = 0;  // Valid only if result == kComplete.
  QuicSocketAddress destination;  // Valid only if result == kComplete.
};

ParsedTransparentHeader ParseQuictunTransparentHeader(absl::string_view buf) {
  if (buf.empty()) {
    return {TransparentHeaderParseResult::kIncomplete};
  }
  uint8_t atyp = static_cast<uint8_t>(buf[0]);
  size_t addr_len;
  if (atyp == 1) {
    addr_len = 4;  // IPv4.
  } else if (atyp == 4) {
    addr_len = 16;  // IPv6.
  } else {
    // Includes ATYP 3 (domain name) -- deliberately unsupported (see this
    // function's own comment) -- and anything else, e.g. a --target-mode
    // client accidentally talking to a --transparent-mode server: its raw
    // TCP payload's first byte is very unlikely to happen to be exactly 1
    // or 4, so mode mismatches like that get caught here, not silently
    // misparsed.
    return {TransparentHeaderParseResult::kInvalid};
  }
  size_t header_length = 1 + addr_len + 2;
  if (buf.size() < header_length) {
    return {TransparentHeaderParseResult::kIncomplete};
  }
  QuicIpAddress ip;
  if (!ip.FromPackedString(buf.data() + 1, addr_len)) {
    return {TransparentHeaderParseResult::kInvalid};
  }
  uint16_t port = (static_cast<uint8_t>(buf[1 + addr_len]) << 8) |
                  static_cast<uint8_t>(buf[1 + addr_len + 1]);
  return {TransparentHeaderParseResult::kComplete, header_length,
          QuicSocketAddress(ip, port)};
}

}  // namespace

std::unique_ptr<QuictunServerConnection> QuictunServerConnection::Create(
    QuicEventLoop* event_loop, QuicConnectionHelperInterface* helper,
    QuicAlarmFactory* alarm_factory, SocketFactory* socket_factory,
    ConnectionIdGeneratorInterface& connection_id_generator,
    const QuicConfig& config, const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache,
    const QuicSocketAddress& listen_address, const QuicSocketAddress& self_address,
    const QuicSocketAddress& peer_address,
    std::optional<QuicSocketAddress> target_address, bool transparent,
    QuicConnectionId server_connection_id,
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
      crypto_config, compressed_certs_cache, target_address, transparent,
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
    std::optional<QuicSocketAddress> target_address, bool transparent,
    QuicConnectionId server_connection_id,
    const std::string& psk, CongestionControlType congestion_control,
    bool so_txtime_enabled, const QuicReceivedPacket& first_packet,
    std::function<void(QuictunServerConnection*)> on_closed)
    : event_loop_(event_loop),
      udp_fd_(std::move(udp_fd)),
      self_address_(self_address),
      peer_address_(peer_address),
      target_address_(target_address),
      transparent_(transparent),
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
  // Snapshot every live tunnel's pointer into a separate vector before
  // touching any of them -- mirrors real QUICHE's own
  // QuicSession::PerformActionOnActiveStreams() (quic_session.cc), the
  // established pattern for exactly this problem: calling each tunnel's
  // own Close() while iterating stream_targets_ directly would reenter
  // through StartTunnelForStream()'s on_closed_ lambda (itself erasing
  // from stream_targets_), invalidating the very map this loop is
  // iterating. A previous version of this code sidestepped that by
  // calling DisconnectStreamTarget() directly instead of going through
  // each tunnel's own Close() -- but that skips ever telling the tunnel
  // itself it's closed (its own closed_ never gets set), so a stream
  // still mid-callback on the same call stack (e.g. servicing a
  // just-received packet for a *different* stream on this connection,
  // itself what triggered this Close() -- QuicConnection::
  // ProcessUdpPacket() reentering all the way back into here the same
  // way a failing write does, see QuictunClientConnection::StartTunnel()'s
  // comment for that mechanism in detail) can still go on to try using
  // its own now-disconnected socket afterward. Confirmed via a real
  // repro (killing the server mid-restart under sustained connection
  // churn) that this crashes on a QUICHE_CHECK in
  // EventLoopConnectingClientSocket::SendInternal(). Snapshotting first,
  // like real QUICHE does, lets every tunnel go through its own real
  // Close() (setting its own closed_, so any still-in-flight reentrant
  // callback correctly no-ops via the check that already guards it --
  // e.g. OnStreamDataAvailable()'s own `if (closed_) return;`) while
  // staying completely safe against stream_targets_ itself changing
  // underneath this loop. closed()-checked before each call since this
  // loop's own reentrancy (one tunnel's Close() closing another one
  // still left in this same snapshot) is exactly what QuictunTunnel::
  // Close()'s own `QUICHE_DCHECK(!closed_)` would otherwise catch.
  std::vector<QuictunTunnel*> tunnels;
  tunnels.reserve(stream_targets_.size());
  for (auto& [id, target] : stream_targets_) {
    tunnels.push_back(target.tunnel.get());
  }
  for (QuictunTunnel* tunnel : tunnels) {
    if (!tunnel->closed()) {
      tunnel->Close("connection closed", /*reset_stream=*/false);
    }
  }
  stream_targets_.clear();
  key_read_buffers_.clear();
  // Cancel, but deliberately do NOT closed_stream_targets_.clear() here.
  // Real crash, found via ASan (heap-use-after-free) on the client-side
  // mirror of this exact code and confirmed to apply here too: whichever
  // tunnel's own stream_->WriteToStream() is what triggered this Close()
  // reentrantly (a failing write, mid QuictunTunnel::ReceiveComplete()/
  // Start()/MaybeCloseAfterQuicFin(), see quictun_tunnel.cc) is still
  // executing further up this exact call stack -- the loop above already
  // moved it into closed_stream_targets_ via its own on_closed_ callback,
  // so clearing that vector synchronously right here would destroy that
  // tunnel out from under itself before its own call stack unwinds back
  // into it. The comment this replaces had it backwards: real QUICHE's
  // QuicSession::OnConnectionClosed() has exactly this same shape
  // (PerformActionOnActiveStreams() moving streams into closed_streams_,
  // possibly including the very one whose write is on the stack right
  // now) and solves it by cancelling closed_streams_clean_up_alarm_
  // (nothing will fire it again) while deliberately leaving
  // closed_streams_ itself alone -- actual destruction happens whenever
  // the owning QuicSession is itself destroyed, deferred by QuicDispatcher.
  // Here that's whenever this whole QuictunServerConnection is destroyed,
  // already safely deferred the same way (see wherever this connection's
  // own on_closed_ callback leads) -- always outside any callback's stack.
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
        size_t offset = 2 + key_length;
        std::optional<QuicSocketAddress> dest;
        bool ready = true;
        if (transparent_) {
          ParsedTransparentHeader parsed = ParseQuictunTransparentHeader(
              absl::string_view(key_read_buffer).substr(offset));
          if (parsed.result == TransparentHeaderParseResult::kInvalid) {
            // Same reasoning as the key-mismatch case above: only this one
            // stream is at fault.
            QUIC_LOG(WARNING)
                << "Rejecting stream " << id << " from " << peer_address_
                << ": invalid or missing transparent-proxy address header";
            stream->Reset(QUIC_BAD_APPLICATION_PAYLOAD);
            key_read_buffers_.erase(id);
            return;
          } else if (parsed.result ==
                     TransparentHeaderParseResult::kIncomplete) {
            // Header hasn't fully arrived yet -- keep reading (falls
            // through to the bytes_read==0 check below).
            ready = false;
          } else {
            dest = parsed.destination;
            offset += parsed.header_length;
          }
        }
        if (ready) {
          authenticated = true;
          // Any bytes already read past the preamble (and address header,
          // if any) are real payload; hand them to the tunnel once it's
          // constructed.
          std::string leftover = key_read_buffer.substr(offset);
          key_read_buffers_.erase(id);
          StartTunnelForStream(id, stream, std::move(leftover), dest);
          return;
        }
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

void QuictunServerConnection::StartTunnelForStream(
    QuicStreamId id, QuictunStream* stream, std::string leftover,
    std::optional<QuicSocketAddress> dest) {
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

  // By construction exactly one of these has a value: OnStreamDataAvailable()
  // only calls this with a real `dest` when transparent_ (and never
  // otherwise), and target_address_ is only nullopt when transparent_ (see
  // --transparent's mutual-exclusivity check in quictun_server_bin.cc).
  QUICHE_DCHECK_EQ(transparent_, dest.has_value());
  QUICHE_DCHECK_EQ(transparent_, !target_address_.has_value());
  const QuicSocketAddress& connect_to = transparent_ ? *dest : *target_address_;

  target.target_socket = socket_factory_->CreateTcpClientSocket(
      connect_to, /*receive_buffer_size=*/0, /*send_buffer_size=*/0,
      target.tunnel.get());
  target.tunnel->SetSocket(target.target_socket.get());
  session_->SetStreamDelegate(id, target.tunnel.get());
  target.target_socket->ConnectAsync();
}

void QuictunServerConnection::OnStreamGone(QuicStreamId id) {
  // Only relevant during a stream's pre-tunnel auth phase (once a
  // QuictunTunnel exists for it, that tunnel -- not this class -- is the
  // stream's delegate, and handles its own OnStreamGone()). The stream
  // closing before finishing authentication needs no further action beyond
  // dropping its now-pointless read buffer -- there is no --target
  // dial-out to clean up yet at this stage.
  key_read_buffers_.erase(id);
}

}  // namespace quic
