// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_client_connection.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_packet_writer.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/tools/quictun_connection_factory.h"
#include "quiche/quic/tools/quictun_session.h"
#include "quiche/quic/tools/quictun_socket_util.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace quic {

namespace {

// Fires stream_garbage_alarm_ -- see that member's comment. Mirrors
// DeleteSessionsAlarm in quic_dispatcher.cc exactly, one level down (and
// see the identical StreamGarbageAlarmDelegate in
// quictun_server_connection.cc for the server-side mirror).
class StreamGarbageAlarmDelegate : public QuicAlarm::DelegateWithoutContext {
 public:
  explicit StreamGarbageAlarmDelegate(QuictunClientConnection* connection)
      : connection_(connection) {}
  StreamGarbageAlarmDelegate(const StreamGarbageAlarmDelegate&) = delete;
  StreamGarbageAlarmDelegate& operator=(const StreamGarbageAlarmDelegate&) =
      delete;

  void OnAlarm() override { connection_->CollectStreamGarbage(); }

 private:
  QuictunClientConnection* const connection_;
};

}  // namespace

std::unique_ptr<QuictunClientConnection> QuictunClientConnection::Create(
    QuicEventLoop* event_loop, QuicConnectionHelperInterface* helper,
    QuicAlarmFactory* alarm_factory,
    ConnectionIdGeneratorInterface& connection_id_generator,
    quiche::QuicheBufferAllocator* buffer_allocator, const QuicConfig& config,
    const QuicServerId& server_id, const QuicSocketAddress& remote_address,
    QuicCryptoClientConfig* crypto_config, const std::string& psk,
    CongestionControlType congestion_control, bool so_txtime_enabled,
    QuicByteCount udp_socket_buffer_bytes, bool poolable, bool transparent,
    std::function<void(QuictunClientConnection*)> on_closed) {
  absl::StatusOr<OwnedSocketFd> fd =
      CreateQuicUdpSocket(remote_address, udp_socket_buffer_bytes);
  if (!fd.ok()) {
    QUIC_LOG(ERROR) << "Failed to create UDP socket for tunnel to "
                    << remote_address << ": " << fd.status();
    return nullptr;
  }
  OwnedSocketFd udp_fd = *std::move(fd);

  absl::Status connect_status = socket_api::Connect(*udp_fd, remote_address);
  if (!connect_status.ok()) {
    QUIC_LOG(ERROR) << "Failed to connect UDP socket to " << remote_address
                    << ": " << connect_status;
    return nullptr;
  }

  absl::StatusOr<QuicSocketAddress> self_address =
      socket_api::GetSocketAddress(*udp_fd);
  if (!self_address.ok()) {
    QUIC_LOG(ERROR) << "Failed to get local address for tunnel UDP socket: "
                    << self_address.status();
    return nullptr;
  }

  // Not using std::make_unique: constructor is private.
  return absl::WrapUnique(new QuictunClientConnection(
      event_loop, std::move(udp_fd), *self_address, remote_address, helper,
      alarm_factory, connection_id_generator, buffer_allocator, config,
      server_id, crypto_config, psk, congestion_control, so_txtime_enabled,
      poolable, transparent, std::move(on_closed)));
}

QuictunClientConnection::QuictunClientConnection(
    QuicEventLoop* event_loop, OwnedSocketFd udp_fd,
    const QuicSocketAddress& self_address,
    const QuicSocketAddress& remote_address, QuicConnectionHelperInterface* helper,
    QuicAlarmFactory* alarm_factory,
    ConnectionIdGeneratorInterface& connection_id_generator,
    quiche::QuicheBufferAllocator* buffer_allocator, const QuicConfig& config,
    const QuicServerId& server_id, QuicCryptoClientConfig* crypto_config,
    const std::string& psk, CongestionControlType congestion_control,
    bool so_txtime_enabled, bool poolable, bool transparent,
    std::function<void(QuictunClientConnection*)> on_closed)
    : event_loop_(event_loop),
      udp_fd_(std::move(udp_fd)),
      self_address_(self_address),
      psk_(psk),
      transparent_(transparent),
      buffer_allocator_(buffer_allocator),
      idle_timeout_(config.IdleNetworkTimeout()),
      on_closed_(std::move(on_closed)) {
  std::unique_ptr<QuicPacketWriter> writer =
      MakeQuictunPacketWriter(*udp_fd_, so_txtime_enabled, event_loop);

  connection_ = std::make_unique<QuicConnection>(
      QuicUtils::CreateRandomConnectionId(), QuicSocketAddress(),
      remote_address, helper, alarm_factory, writer.release(),
      /*owns_writer=*/true, Perspective::IS_CLIENT, GetQuictunVersions(),
      connection_id_generator);
  SetQuictunCongestionControl(connection_.get(), congestion_control);

  session_ = std::make_unique<QuictunClientSession>(
      connection_.get(), /*owner=*/this, config, "quictun/1", server_id,
      crypto_config, poolable);
  session_->SetCanOpenStreamCallback([this] { MaybeOpenStreams(); });
  session_->Initialize();

  // See closed_stream_tcps_/stream_garbage_alarm_'s comments -- mirrors
  // QuicSession's own closed_streams_clean_up_alarm_ construction exactly.
  stream_garbage_alarm_.reset(
      alarm_factory->CreateAlarm(new StreamGarbageAlarmDelegate(this)));

  // kSocketEventError: see QuictunServerConnection's identical
  // RegisterSocket() comment for the full story. Same exposure here --
  // this socket is connect()ed to --remote (see Create() above), so it
  // latches ICMP into SO_ERROR, poll() reports that as an unmaskable
  // POLLERR, and an unsubscribed POLLERR is masked away and dispatched to
  // nobody, spinning the event loop at 100% CPU. Mirrored on both sides
  // rather than only where it was first reproduced (server, when a client
  // vanished): the client hits exactly the same thing whenever the server
  // is the one that disappears abruptly.
  bool registered = event_loop_->RegisterSocket(
      *udp_fd_,
      kSocketEventReadable | kSocketEventWritable | kSocketEventError, this);
  QUICHE_DCHECK(registered);

  session_->CryptoConnect();
}

void QuictunClientConnection::AssignNewTcp(
    SocketFd accepted_tcp_fd, const QuicSocketAddress& tcp_peer_address,
    std::optional<QuicSocketAddress> captured_dest) {
  if (closed_) {
    socket_api::Close(accepted_tcp_fd);
    return;
  }
  QUICHE_DCHECK_EQ(transparent_, captured_dest.has_value());
  pending_tcps_.push_back({accepted_tcp_fd, tcp_peer_address, captured_dest});
  // Try right away -- succeeds immediately when a cached 0-RTT session (or,
  // under pooling, this connection's own already-confirmed handshake) has
  // already supplied a max_streams value allowing it. Otherwise this is a
  // no-op and MaybeOpenStreams() gets retried from
  // SetCanOpenStreamCallback() once QuicSession actually applies one (from
  // the negotiated transport parameters, for a fresh non-0-RTT connection,
  // or a later MAX_STREAMS frame).
  MaybeOpenStreams();
}

void QuictunClientConnection::MaybeOpenStreams() {
  while (!closed_ && !pending_tcps_.empty()) {
    QuictunStream* stream = session_->OpenOutgoingStream();
    if (stream == nullptr) {
      return;
    }
    PendingTcp pending = pending_tcps_.front();
    pending_tcps_.pop_front();
    StartTunnel(stream, pending);
  }
}

void QuictunClientConnection::StartTunnel(QuictunStream* stream,
                                          PendingTcp pending) {
  // quictun's own authentication: --key, sent as a length-prefixed preamble
  // (2-byte big-endian length + key bytes) that must always be the very
  // first bytes on the stream. This exists because
  // QuicCryptoClientConfig::set_pre_shared_key() -- the "real" TLS 1.3
  // external-PSK mechanism -- turns out to be unimplemented for TLS-based
  // QUIC in this snapshot (TlsClientHandshaker::CryptoConnect() hard-crashes
  // via QUIC_BUG if it's set; see quictun_client_driver.cc's comment). This
  // is a strictly weaker authentication property than a real TLS-level PSK
  // (it doesn't bind the key into the handshake's key schedule, so it can't
  // by itself defeat an active on-path attacker who completes the TLS
  // handshake with the client -- the client never validates the server's
  // certificate at all, see FakeProofVerifier), but matches this tool's
  // explicitly low security bar: it rejects any connection that doesn't
  // know the shared secret. Sent fresh on every stream (not just this
  // connection's first), one per TCP tunnel -- see
  // QuictunServerConnection::OnStreamDataAvailable for the server-side
  // check, done the same way, once per stream.
  std::string preamble;
  preamble.push_back(static_cast<char>((psk_.size() >> 8) & 0xff));
  preamble.push_back(static_cast<char>(psk_.size() & 0xff));
  preamble.append(psk_);
  if (transparent_) {
    // ss-server-style address header (1-byte ATYP + raw address + 2-byte
    // big-endian port), IPv4/IPv6 only -- no domain-name ATYP, since this
    // is always a concrete IP captured off SO_ORIGINAL_DST, never a
    // hostname. Sent as part of the same preamble write, right after the
    // key, so this doesn't cost an extra round trip -- see
    // QuictunServerConnection::OnStreamDataAvailable() for the matching
    // parse. pending.captured_dest always has a value here: AssignNewTcp()
    // requires one whenever this connection was constructed with
    // transparent_ (see its own comment/QUICHE_DCHECK).
    const QuicSocketAddress& dest = *pending.captured_dest;
    bool is_ipv6 = dest.host().address_family() == IpAddressFamily::IP_V6;
    preamble.push_back(is_ipv6 ? 4 : 1);
    preamble.append(dest.host().ToPackedString());
    uint16_t port = dest.port();
    preamble.push_back(static_cast<char>((port >> 8) & 0xff));
    preamble.push_back(static_cast<char>(port & 0xff));
  }
  stream->WriteToStream(preamble, /*fin=*/false);
  // WriteToStream() above can synchronously tear down this whole
  // connection: a failing UDP write (e.g. --remote unreachable right this
  // instant, routine during a peer restart) is something
  // QuicConnection::OnWriteError() reacts to by synchronously closing the
  // connection then and there, reentrantly, all the way up through
  // OnConnectionClosed() -> Close() -- the identical mechanism already
  // described in detail on QuictunTunnel::Close()'s own on_closed_-before-
  // Reset() ordering comment. Close() (which sets closed_) always runs to
  // completion before control returns here -- QuicConnection has its own
  // in_close_connection_ reentrancy guard, so this can't recurse further
  // -- including already queuing *this* connection for destruction via
  // on_closed_. But it ran with stream_tcps_ exactly as it looked before
  // this call (this stream's entry doesn't exist yet), so it has no way
  // to know about -- and so no way to clean up -- the TCP this call was
  // in the middle of setting up. Bail out here instead of falling
  // through to add a stray entry into a stream_tcps_ a Close() already
  // ran against and assumed was fully accounted for: confirmed via a
  // real repro (killing the server mid-restart under sustained
  // connection churn) that falling through crashes on a QUICHE_DCHECK in
  // ~QuictunAcceptedTcpSocket() ("Must call Disconnect() before
  // destruction") once CollectGarbage() actually destroys this
  // already-queued-for-removal connection with that stray entry still
  // sitting in stream_tcps_, its tcp_socket never Disconnect()ed.
  // Matches real QUICHE's own idiom for this exact class of hazard --
  // re-checking state immediately after anything that writes, before
  // trusting it's still valid to keep going -- see e.g. quic_session.cc's
  // dozens of "if (!connection_->connected())" checks following writes;
  // closed_ here is the narrower, already-latched equivalent (Close() is
  // the only thing that could have just run reentrantly, and it's what
  // sets this).
  if (closed_) {
    socket_api::Close(pending.fd);
    return;
  }

  QuicStreamId id = stream->id();
  StreamTcp& entry = stream_tcps_[id];
  // QuictunTunnel and QuictunAcceptedTcpSocket each need a pointer to the
  // other at construction (tunnel needs the socket to pump through; the
  // socket needs the tunnel as its AsyncVisitor) -- construct the socket
  // with no visitor yet, then wire it up once the tunnel exists.
  entry.tcp_socket = std::make_unique<QuictunAcceptedTcpSocket>(
      pending.fd, pending.peer_address, event_loop_, buffer_allocator_,
      /*async_visitor=*/nullptr);
  entry.tunnel = std::make_unique<QuictunTunnel>(
      stream, entry.tcp_socket.get(), idle_timeout_, [this, id] {
        // This stream's tunnel closed itself -- scoped to just this one
        // TCP, same reasoning as the server-side mirror of this callback
        // (QuictunServerConnection::StartTunnelForStream()): other streams
        // sharing this connection (--quic_conn pooling) may still be
        // actively tunneling and shouldn't be torn down just because one
        // of them finished. QuictunTunnel::Close() always disconnects
        // tcp_socket_ itself when it has one (unlike the server's
        // dial-out, this one is always already connected by the time the
        // tunnel exists -- see the constructor -- so HasSocket() is always
        // true here; no need for QuictunServerConnection's extra check).
        //
        // Same use-after-free hazard as the server-side mirror, and the
        // same fix -- see QuictunServerConnection::StartTunnelForStream()'s
        // comment in full: this callback runs from inside
        // QuictunTunnel::Close(), a member function of the very
        // QuictunTunnel that entry.tunnel owns, which keeps executing
        // after this callback returns, so it can't synchronously destroy
        // the StreamTcp here. Mirrors QuicSession::
        // PrepareStreamForDestruction() exactly: move out of the live map
        // into closed_stream_tcps_ (not destroyed yet) and arm
        // stream_garbage_alarm_ to actually destroy it outside this call
        // stack -- with session_->ClearStreamDelegate(id) happening in
        // this exact same synchronous step, closing the same
        // delegate-outlives-its-destroyed-owner window found via a real
        // core dump on the server side (same underlying bug, same fix,
        // this class just hasn't been observed crashing from it yet).
        auto it = stream_tcps_.find(id);
        if (it == stream_tcps_.end()) {
          return;
        }
        it->second.tcp_socket_disconnected = true;
        session_->ClearStreamDelegate(id);
        closed_stream_tcps_.push_back(std::move(it->second));
        stream_tcps_.erase(it);
        if (!stream_garbage_alarm_->IsSet()) {
          stream_garbage_alarm_->Set(event_loop_->GetClock()->ApproximateNow());
        }
      });
  entry.tcp_socket->SetAsyncVisitor(entry.tunnel.get());
  session_->SetStreamDelegate(id, entry.tunnel.get());
  entry.tunnel->Start();
}

void QuictunClientConnection::CollectStreamGarbage() {
  // See closed_stream_tcps_'s comment. This is the actual destruction -- of
  // the StreamTcp, and with it the QuictunTunnel and tcp_socket -- now
  // safely outside any tunnel's own call stack (this only ever runs from
  // stream_garbage_alarm_ firing).
  closed_stream_tcps_.clear();
}

QuictunClientConnection::~QuictunClientConnection() {
  if (event_loop_->UnregisterSocket(*udp_fd_)) {
    // Expected: still registered unless Close() already ran.
  }
}

void QuictunClientConnection::Close() {
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
  // touching any of them -- see the identical reasoning (and the real
  // crash it was found from) in QuictunServerConnection::Close()'s
  // matching comment; mirrors real QUICHE's own QuicSession::
  // PerformActionOnActiveStreams() (quic_session.cc). Matters most under
  // --quic_conn pooling (more than one tunnel sharing this connection --
  // --quic_conn=0 only ever has the one, so there's no *sibling* tunnel
  // for this loop's own reentrancy to reach) but applied here
  // unconditionally to match the server side exactly rather than special-
  // casing quic_conn==0.
  std::vector<QuictunTunnel*> tunnels;
  tunnels.reserve(stream_tcps_.size());
  for (auto& [id, entry] : stream_tcps_) {
    tunnels.push_back(entry.tunnel.get());
  }
  for (QuictunTunnel* tunnel : tunnels) {
    if (!tunnel->closed()) {
      tunnel->Close("connection closed", /*reset_stream=*/false);
    }
  }
  stream_tcps_.clear();
  // Cancel, but deliberately do NOT closed_stream_tcps_.clear() here --
  // see QuictunServerConnection::Close()'s identical comment for the full
  // real-crash story (this is the fix for it): whichever tunnel's own
  // stream_->WriteToStream() is what triggered this Close() reentrantly
  // (a failing write, mid QuictunTunnel::ReceiveComplete()/Start()/
  // MaybeCloseAfterQuicFin(), see quictun_tunnel.cc) is still executing
  // further up this exact call stack, and the loop above already moved
  // it into closed_stream_tcps_ via its own on_closed_ callback --
  // clearing that vector synchronously right here would destroy that
  // tunnel out from under itself before its own call stack unwinds back
  // into it, a real reproduced-under-ASan use-after-free. Real QUICHE's
  // QuicSession::OnConnectionClosed() has exactly this same shape and
  // solves it the same way: cancel closed_streams_clean_up_alarm_
  // (nothing will fire it again) but leave closed_streams_ itself alone
  // -- actual destruction happens whenever the owning object is itself
  // destroyed. Here that's whenever this whole QuictunClientConnection
  // is destroyed, already safely deferred to CollectGarbage() in
  // quictun_client_driver.cc -- always outside any callback's stack, the
  // same guarantee QuicDispatcher's own deferred session destruction
  // gives QuicSession.
  stream_garbage_alarm_->Cancel();
  // Any TCPs that never even got a stream opened for them yet: nothing
  // owns these but this queue, so close the raw fd directly.
  for (const PendingTcp& pending : pending_tcps_) {
    socket_api::Close(pending.fd);
  }
  pending_tcps_.clear();
  event_loop_->UnregisterSocket(*udp_fd_);
  std::function<void(QuictunClientConnection*)> on_closed =
      std::move(on_closed_);
  if (on_closed) {
    on_closed(this);
  }
}

void QuictunClientConnection::OnConnectionClosed(
    QuicConnectionId /*server_connection_id*/, QuicErrorCode error,
    const std::string& error_details, ConnectionCloseSource source) {
  // EarlyDataAccepted()/EarlyDataReason() are only meaningful (and only
  // safe to call -- TlsClientHandshaker::EarlyDataAccepted() itself
  // QUIC_BUG_IFs otherwise) once the handshake has actually produced 1-RTT
  // keys. A connection that never gets that far (e.g. ECONNREFUSED before
  // any handshake progress) hits this constantly, spamming an unrelated,
  // message-less quic_bug_12736_2 on every single closed attempt.
  if (session_->OneRttKeysAvailable()) {
    QUIC_LOG(INFO) << "quictun connection closed: "
                   << QuicErrorCodeToString(error) << " (\"" << error_details
                   << "\"), source="
                   << (source == ConnectionCloseSource::FROM_PEER ? "PEER"
                                                                   : "SELF")
                   << ", EarlyDataAccepted=" << session_->EarlyDataAccepted()
                   << " EarlyDataReason=" << session_->EarlyDataReason();
  } else {
    QUIC_LOG(INFO) << "quictun connection closed: "
                   << QuicErrorCodeToString(error) << " (\"" << error_details
                   << "\"), source="
                   << (source == ConnectionCloseSource::FROM_PEER ? "PEER"
                                                                   : "SELF")
                   << " (handshake never completed)";
  }
  Close();
}

void QuictunClientConnection::OnSocketEvent(QuicEventLoop* /*event_loop*/,
                                            SocketFd fd,
                                            QuicSocketEventMask events) {
  QUICHE_DCHECK_EQ(fd, *udp_fd_);
  // Before the readable/writable branches: a recvmsg() on a socket with a
  // pending SO_ERROR returns that error rather than any data queued
  // behind it. See ConsumePendingSocketError().
  if (events & kSocketEventError) {
    ConsumePendingSocketError();
  }
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

void QuictunClientConnection::ConsumePendingSocketError() {
  // See QuictunServerConnection::ConsumePendingSocketError() for the full
  // reasoning; this is its exact mirror. Short version: reading SO_ERROR
  // is what clears the kernel's latched error, without which poll() keeps
  // reporting an unsubscribed POLLERR forever and the event loop stops
  // sleeping; and the error is deliberately only consumed and logged,
  // never acted on, since ICMP is spoofable and transient unreachables
  // are normal -- QUIC's own idle timeout decides the connection's fate.
  absl::Status error = socket_api::GetSocketError(*udp_fd_);
  if (!error.ok()) {
    QUIC_LOG_EVERY_N_SEC(INFO, 10)
        << "quictun connection to " << connection_->peer_address()
        << " got a socket error (peer may be gone): " << error
        << " -- consumed; leaving the connection's fate to QUIC's own "
           "idle timeout";
  }
  if (!event_loop_->SupportsEdgeTriggered()) {
    event_loop_->RearmSocket(*udp_fd_, kSocketEventError);
  }
}

void QuictunClientConnection::ProcessPacket(
    const QuicSocketAddress& self_address, const QuicSocketAddress& peer_address,
    const QuicReceivedPacket& packet) {
  // Unlike QuictunServerConnection::ProcessPacket(), this doesn't need to
  // override `peer_address` with a cached canonical value: the client's UDP
  // socket is created for `remote_address`'s own address family (see
  // Create()), never a dual-stack wildcard, so QuicPacketReader's
  // v4-mapped-address normalization never disagrees with what the socket
  // actually speaks or what QuicConnection was constructed with.
  connection_->ProcessUdpPacket(self_address, peer_address, packet);
}

}  // namespace quic
