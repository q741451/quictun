// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_tunnel.h"

#include <algorithm>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_mem_slice.h"

namespace quic {

namespace {

// How long MaybeFinalizeClose() waits, total, for the stream to finish
// sending before giving up on a clean flush and closing anyway. A couple of
// RTTs' worth even on quictun's own worse-case tested path (~200ms RTT, see
// the congestion-control tuning flags) plus room for one retransmission.
constexpr QuicTime::Delta kMaxFlushCloseWait = QuicTime::Delta::FromSeconds(3);
constexpr QuicTime::Delta kFlushCloseRetryInterval =
    QuicTime::Delta::FromMilliseconds(100);

class FlushCloseAlarmDelegate : public QuicAlarm::DelegateWithoutContext {
 public:
  explicit FlushCloseAlarmDelegate(QuictunTunnel* tunnel) : tunnel_(tunnel) {}
  void OnAlarm() override { tunnel_->OnFlushCloseAlarm(); }

 private:
  QuictunTunnel* const tunnel_;
};

class IdleAlarmDelegate : public QuicAlarm::DelegateWithoutContext {
 public:
  explicit IdleAlarmDelegate(QuictunTunnel* tunnel) : tunnel_(tunnel) {}
  void OnAlarm() override { tunnel_->OnIdleAlarm(); }

 private:
  QuictunTunnel* const tunnel_;
};

}  // namespace

QuictunTunnel::QuictunTunnel(QuictunStream* stream, ConnectingClientSocket* socket,
                             QuicTime::Delta idle_timeout,
                             std::function<void()> on_closed)
    : stream_(stream),
      socket_(socket),
      on_closed_(std::move(on_closed)),
      idle_timeout_(idle_timeout) {}

void QuictunTunnel::Start(absl::string_view seed_quic_to_tcp_data) {
  if (!seed_quic_to_tcp_data.empty()) {
    pending_to_tcp_.push_back(std::string(seed_quic_to_tcp_data));
  }
  ResetIdleAlarm();
  // Pick up anything the stream's sequencer is already holding from before
  // this tunnel existed as its delegate: on the server side in particular,
  // QuictunServerConnection reads only up through the --key preamble itself
  // (see its OnStreamDataAvailable()), then stops reading -- deliberately,
  // matching QUICHE's own connect_tunnel.cc pattern of leaving
  // not-yet-wanted data safely unread in the sequencer rather than copying
  // it into an application-level buffer -- once authenticated, until this
  // tunnel is actually constructed (which on the server waits on the
  // --target dial-out, a real async connect that can take real time). Any
  // stream data that arrives during that window sits safely buffered by
  // QUIC's own flow control, but SetStreamDelegate() switching the active
  // delegate over to this tunnel is a plain pointer assignment with no
  // side effects -- it does not itself re-deliver an OnDataAvailable()
  // notification for already-arrived data, and the peer has no reason to
  // send anything more once it's already said everything it needs to.
  // Without this call, that data would simply never be read, indefinitely.
  FillQueueFromStream();
  BeginReadFromTcp();
  MaybeFlushQuicToTcp();
}

void QuictunTunnel::OnStreamDataAvailable() {
  if (closed_) {
    return;
  }
  FillQueueFromStream();
  MaybeFlushQuicToTcp();
}

void QuictunTunnel::OnStreamCanWriteMore() {
  if (closed_) {
    return;
  }
  if (tcp_receive_done_) {
    // More write capacity freeing up is a reasonable proxy for "some
    // previously-sent data just got acked" -- an opportunistic early check,
    // cheaper than waiting out flush_close_alarm_'s full retry interval.
    MaybeFinalizeClose();
    return;
  }
  // Strict backpressure, mirroring shadowsocks-libev's remote_recv_cb/
  // server_send_cb pair (server.c): only resume reading from the TCP side
  // once every previously-read byte has actually been handed off by the
  // stream (HasBufferedData() false), not just once there's *some* room
  // (the old CanBufferMoreWrites() check). This makes "we just read EOF"
  // and "we still have unsent data from a previous read" structurally
  // mutually exclusive, the same way ss-libev's io-watcher toggling does --
  // see ReceiveComplete()'s empty-data branch, which no longer needs to
  // assume there might be unflushed data sitting around from a *previous*
  // read (flush_close_alarm_ still guards the *current*, just-written fin).
  if (tcp_receive_in_flight_ || stream_->HasBufferedData()) {
    return;
  }
  BeginReadFromTcp();
}

void QuictunTunnel::OnStreamClosed() {
  if (closed_) {
    return;
  }
  // The QUIC stream reached its natural end (FIN both ways acknowledged, or
  // a reset) on its own -- nothing left to forward in either direction, so
  // just release the TCP socket and let the owner tear the rest down.
  Close("stream closed", /*reset_stream=*/false);
}

void QuictunTunnel::ConnectComplete(absl::Status /*status*/) {
  // Never called: the owner is responsible for connecting `socket_` (or, for
  // an already-accepted TCP connection, there is nothing to connect) before
  // handing it to this tunnel, exactly as with connect_tunnel.cc's own
  // ConnectComplete().
  QUICHE_NOTREACHED();
}

void QuictunTunnel::ReceiveComplete(
    absl::StatusOr<quiche::QuicheMemSlice> data) {
  tcp_receive_in_flight_ = false;
  if (closed_) {
    return;
  }
  if (!data.ok()) {
    Close("TCP receive error", /*reset_stream=*/true);
    return;
  }
  if (data->empty()) {
    // TCP peer closed its write side: forward as a QUIC FIN, then tear the
    // whole tunnel down once that -- and anything written to the stream
    // before it -- has actually finished sending, rather than waiting for
    // the QUIC stream's own other direction to also independently finish
    // (mirroring QUICHE's own connect_tunnel.cc: OnDestinationConnectionClosed()
    // unconditionally Disconnect()s and closes the client stream too).
    // ConnectingClientSocket has no shutdown(SHUT_WR)-equivalent half-close,
    // so there's no way to signal "no more data is coming from me" without
    // giving up on receiving any more either -- and waiting for the peer to
    // close on its own is what let closed TCP targets pile up as leaked
    // connections forever (see the comment on quic_receive_done_ in the
    // header). See MaybeFinalizeClose() for why this can't just close
    // immediately, though: see tcp_receive_done_'s comment.
    tcp_receive_done_ = true;
    send_done_time_ = stream_->connection()->clock()->ApproximateNow();
    stream_->WriteToStream("", /*fin=*/true);
    MaybeFinalizeClose();
    return;
  }
  ResetIdleAlarm();
  stream_->WriteToStream(data->AsStringView(), /*fin=*/false);
  // Strict backpressure -- see OnStreamCanWriteMore()'s comment: don't read
  // more until this write has fully drained, so a *later* EOF can never
  // land on top of still-unsent data from here.
  if (!stream_->HasBufferedData()) {
    BeginReadFromTcp();
  }
  // Otherwise wait for OnStreamCanWriteMore() to resume reading from TCP.
}

void QuictunTunnel::SendComplete(absl::Status status) {
  tcp_send_in_flight_ = false;
  if (closed_) {
    return;
  }
  if (!status.ok()) {
    Close("TCP send error", /*reset_stream=*/true);
    return;
  }
  // A queue slot just freed up: top it back up from the stream in case a
  // prior burst left unread data buffered there (see FillQueueFromStream's
  // comment) before flushing whatever's now queued.
  FillQueueFromStream();
  MaybeFlushQuicToTcp();
}

void QuictunTunnel::FillQueueFromStream() {
  while (pending_to_tcp_.size() < kMaxQueuedChunks) {
    std::string buffer(kReadSize, '\0');
    bool fin = false;
    size_t bytes_read =
        stream_->Read(absl::MakeSpan(&buffer[0], buffer.size()), &fin);
    if (bytes_read > 0) {
      ResetIdleAlarm();
      buffer.resize(bytes_read);
      pending_to_tcp_.push_back(std::move(buffer));
    }
    if (fin) {
      // No more QUIC->TCP data will ever arrive. Don't tear the tunnel down
      // here directly, though: `buffer` above may have just captured the
      // final real chunk that came with this FIN, still sitting unsent in
      // pending_to_tcp_ -- see MaybeCloseAfterQuicFin(), invoked once that's
      // actually been flushed.
      quic_receive_done_ = true;
      break;
    }
    if (bytes_read == 0) {
      break;
    }
  }
}

void QuictunTunnel::BeginReadFromTcp() {
  if (closed_ || tcp_receive_in_flight_ || tcp_receive_done_) {
    return;
  }
  tcp_receive_in_flight_ = true;
  socket_->ReceiveAsync(kReadSize);
}

void QuictunTunnel::MaybeFlushQuicToTcp() {
  if (closed_ || tcp_send_in_flight_) {
    return;
  }
  if (pending_to_tcp_.empty()) {
    MaybeCloseAfterQuicFin();
    return;
  }
  std::string chunk = std::move(pending_to_tcp_.front());
  pending_to_tcp_.pop_front();
  tcp_send_in_flight_ = true;
  socket_->SendAsync(std::move(chunk));
}

void QuictunTunnel::MaybeCloseAfterQuicFin() {
  if (closed_ || !quic_receive_done_) {
    return;
  }
  // mirroring connect_tunnel.cc's OnClientStreamClose(): the peer is done
  // sending and we've forwarded everything it sent, so treat our own send
  // direction as finished too -- nothing else will ever need relaying to
  // `socket_` -- rather than waiting on the TCP target to also decide to
  // close on its own, which, for a target that itself expects the client to
  // hang up first, may never happen (see the comment on quic_receive_done_
  // in the header). Actual teardown still goes through MaybeFinalizeClose():
  // see tcp_receive_done_'s comment for why this can't just close the
  // connection immediately, the same as the ReceiveComplete()-driven path.
  if (!tcp_receive_done_) {
    tcp_receive_done_ = true;
    send_done_time_ = stream_->connection()->clock()->ApproximateNow();
    stream_->WriteToStream("", /*fin=*/true);
  }
  MaybeFinalizeClose();
}

void QuictunTunnel::MaybeFinalizeClose() {
  if (closed_ || !tcp_receive_done_) {
    return;
  }
  if (!stream_->HasBufferedData() && !stream_->IsWaitingForAcks()) {
    if (flush_close_alarm_) {
      flush_close_alarm_->Cancel();
    }
    Close("tunnel finished", /*reset_stream=*/false);
    return;
  }
  QuicConnection* connection = stream_->connection();
  QuicTime now = connection->clock()->ApproximateNow();
  if (now - send_done_time_ >= kMaxFlushCloseWait) {
    // Waited long enough -- either the peer is gone and nothing will ever
    // ack, or something else is stuck. Don't hang the tunnel open forever;
    // close anyway, same tradeoff idle_timeout makes at a coarser grain.
    QUICHE_LOG(WARNING) << "Giving up waiting for stream flush after "
                        << kMaxFlushCloseWait << ", closing anyway"
                        << " (HasBufferedData=" << stream_->HasBufferedData()
                        << ", IsWaitingForAcks=" << stream_->IsWaitingForAcks()
                        << ")";
    if (flush_close_alarm_) {
      flush_close_alarm_->Cancel();
    }
    Close("tunnel finished (flush wait exceeded)", /*reset_stream=*/false);
    return;
  }
  if (!flush_close_alarm_) {
    flush_close_alarm_.reset(
        connection->alarm_factory()->CreateAlarm(new FlushCloseAlarmDelegate(this)));
  }
  QuicTime deadline = std::min(now + kFlushCloseRetryInterval,
                               send_done_time_ + kMaxFlushCloseWait);
  if (!flush_close_alarm_->IsSet() || flush_close_alarm_->deadline() > deadline) {
    flush_close_alarm_->Update(deadline, QuicTime::Delta::Zero());
  }
}

void QuictunTunnel::OnFlushCloseAlarm() { MaybeFinalizeClose(); }

void QuictunTunnel::ResetIdleAlarm() {
  if (closed_) {
    return;
  }
  if (!idle_alarm_) {
    idle_alarm_.reset(stream_->connection()->alarm_factory()->CreateAlarm(
        new IdleAlarmDelegate(this)));
  }
  idle_alarm_->Update(
      stream_->connection()->clock()->ApproximateNow() + idle_timeout_,
      QuicTime::Delta::Zero());
}

void QuictunTunnel::OnIdleAlarm() {
  if (closed_) {
    return;
  }
  // Mirrors shadowsocks-libev's server_timeout_cb: nothing productive has
  // happened on either leg for idle_timeout_ -- most likely socket_ is
  // connected to a target/peer that itself expects *us* to send the next
  // byte, which (since the tunnel got here) will never come. Give up rather
  // than hold the fd pair open forever; see idle_alarm_'s comment.
  Close("idle timeout", /*reset_stream=*/true);
}

void QuictunTunnel::Close(absl::string_view reason, bool reset_stream) {
  QUICHE_DCHECK(!closed_);
  closed_ = true;
  if (flush_close_alarm_) {
    flush_close_alarm_->Cancel();
  }
  if (idle_alarm_) {
    idle_alarm_->Cancel();
  }
  QUICHE_LOG(INFO) << "Closing quictun tunnel: " << reason
                   << ", reset_stream=" << reset_stream;
  socket_->Disconnect();

  // on_closed_ before stream_->Reset(), not after: on_closed_ synchronously
  // runs the owner's own Close() (QuictunServerConnection::Close() /
  // QuictunClientConnection::Close()), which tears down the whole
  // connection_ (CloseConnection()) and marks *its* record of socket_ as
  // disconnected. Only after that has genuinely finished is it safe to
  // attempt stream_->Reset() -- which needs to write a RST_STREAM packet,
  // and a failing write is itself something QuicConnection::OnWriteError()
  // reacts to by synchronously tearing down the connection right then and
  // there (see QuicConnection::CloseConnection()'s own in_close_connection_
  // reentrancy guard for the general pattern this mirrors). With the old
  // ordering (Reset() before on_closed_), that synchronous teardown would
  // reenter QuictunServerConnection::OnConnectionClosed() -> Close() while
  // it still believed target_socket_ hadn't been disconnected yet (that
  // bookkeeping only happens inside the on_closed_ callback, which hadn't
  // run yet) -- and calling Disconnect() on the already-disconnected
  // socket_ from within that reentrant call hit a fatal
  // QUICHE_CHECK(descriptor_ != kInvalidSocketFd) in
  // EventLoopConnectingClientSocket::Disconnect(). Reordering so on_closed_
  // completes first means that check is already correctly up to date by
  // the time (if ever) a write failure during Reset() triggers the same
  // reentrant path -- and skipping Reset() once the connection is already
  // gone (below) means that reentrant path is no longer even reachable in
  // the first place.
  std::function<void()> on_closed = std::move(on_closed_);
  if (on_closed) {
    on_closed();
  }

  // Only now, after the owner has had its chance to fully close the
  // connection above -- see the comment above on_closed's invocation. If it
  // already did (the common case: the owner's Close() always closes
  // connection_ if still connected), connection() is already disconnected
  // and Reset() would have nothing to actually send, so skip it outright
  // rather than attempt (and possibly fail) a pointless write.
  if (reset_stream && stream_->connection()->connected()) {
    stream_->Reset(QUIC_STREAM_CANCELLED);
  }
}

}  // namespace quic
