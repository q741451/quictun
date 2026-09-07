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
    bool poolable, bool transparent,
    const QuicSocketAddress& self_address, QuicPacketWriter* shared_writer,
    QuicConnectionId client_connection_id, QuictunIdleTracker* idle_tracker,
    std::function<void(QuicBlockedWriterInterface*)> on_write_blocked,
    std::function<void(QuictunClientConnection*)> on_closed) {
  // Not using std::make_unique: constructor is private.
  return absl::WrapUnique(new QuictunClientConnection(
      event_loop, self_address, remote_address, helper,
      alarm_factory, connection_id_generator, buffer_allocator, config,
      server_id, crypto_config, psk, congestion_control, so_txtime_enabled,
      poolable, transparent, shared_writer, client_connection_id,
      idle_tracker, std::move(on_write_blocked), std::move(on_closed)));
}

QuictunClientConnection::QuictunClientConnection(
    QuicEventLoop* event_loop,
    const QuicSocketAddress& self_address,
    const QuicSocketAddress& remote_address, QuicConnectionHelperInterface* helper,
    QuicAlarmFactory* alarm_factory,
    ConnectionIdGeneratorInterface& connection_id_generator,
    quiche::QuicheBufferAllocator* buffer_allocator, const QuicConfig& config,
    const QuicServerId& server_id, QuicCryptoClientConfig* crypto_config,
    const std::string& psk, CongestionControlType congestion_control,
    bool so_txtime_enabled, bool poolable, bool transparent,
    QuicPacketWriter* shared_writer, QuicConnectionId client_connection_id,
    QuictunIdleTracker* idle_tracker,
    std::function<void(QuicBlockedWriterInterface*)> on_write_blocked,
    std::function<void(QuictunClientConnection*)> on_closed)
    : event_loop_(event_loop),
      self_address_(self_address),
      psk_(psk),
      transparent_(transparent),
      buffer_allocator_(buffer_allocator),
      idle_tracker_(idle_tracker),
      on_write_blocked_(std::move(on_write_blocked)),
      on_closed_(std::move(on_closed)) {
  // Borrowed: the driver owns one writer over the one shared UDP socket.
  connection_ = std::make_unique<QuicConnection>(
      QuicUtils::CreateRandomConnectionId(), QuicSocketAddress(),
      remote_address, helper, alarm_factory, shared_writer,
      /*owns_writer=*/false, Perspective::IS_CLIENT, GetQuictunVersions(),
      connection_id_generator);
  // What the server will address its packets to, and therefore the only
  // thing the driver can demultiplex a shared socket's reads on -- a 1-RTT
  // short header carries no source connection ID. Client CIDs never rotate
  // here: QuicConnection only re-issues them on path migration, and this
  // connection never migrates.
  connection_->set_client_connection_id(client_connection_id);
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
    // SOCKS5-style address header (1-byte ATYP + raw address + 2-byte
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
      stream, entry.tcp_socket.get(), idle_tracker_, [this, id] {
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
