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

void CloseExpired(quiche::QuicheIntrusiveList<QuictunTunnel>& list,
                  QuicTime now, QuicTime::Delta timeout,
                  absl::string_view reason) {
  // Oldest activity is at the front, so the front is the only candidate: if
  // it isn't expired, nothing is.
  while (!list.empty() && now - list.front().last_activity() >= timeout) {
    QuictunTunnel* tunnel = &list.front();
    tunnel->Close(reason, /*reset_stream=*/true);
    // Close() unlinks before it can reenter anything (see its own body), so
    // the front always advances and this loop always terminates. Asserted
    // rather than defended against: a Close() that stopped unlinking would
    // spin here forever, and catching that in a debug run beats shipping a
    // silent bound.
    QUICHE_DCHECK(list.empty() || &list.front() != tunnel);
  }
}

}  // namespace

void QuictunIdleTracker::Touch(QuictunTunnel* tunnel, bool stalled) {
  quiche::QuicheIntrusiveList<QuictunTunnel>& list =
      stalled ? stalled_order_ : order_;
  if (!list.empty() && &list.back() == tunnel) {
    // Already the most recently active in the class it belongs to -- the
    // overwhelmingly common case for a tunnel that is actively
    // transferring, and for any connection carrying only one.
    return;
  }
  Remove(tunnel);
  // The sweep only ever looks at the front, which is sound only while each
  // list is ordered oldest-first. That holds by construction rather than by
  // any sorting step, so the one thing that could break it is appending an
  // entry older than the current tail -- checked here, where it is O(1),
  // instead of validating the whole list from the sweep.
  QUICHE_DCHECK(list.empty() ||
                list.back().last_activity() <= tunnel->last_activity());
  list.push_back(tunnel);
}

void QuictunIdleTracker::Refile(QuictunTunnel* tunnel, bool stalled) {
  if (!quiche::QuicheIntrusiveList<QuictunTunnel>::is_linked(tunnel)) {
    return;
  }
  Touch(tunnel, stalled);
}

void QuictunIdleTracker::Remove(QuictunTunnel* tunnel) {
  using List = quiche::QuicheIntrusiveList<QuictunTunnel>;
  if (List::is_linked(tunnel)) {
    List::erase(tunnel);
  }
}

void QuictunIdleTracker::CloseIdleTunnels(QuicTime now,
                                          QuicTime::Delta timeout,
                                          QuicTime::Delta stalled_timeout) {
  CloseExpired(order_, now, timeout, "idle timeout");
  CloseExpired(stalled_order_, now, stalled_timeout, "stalled timeout");
}

QuictunTunnel::QuictunTunnel(QuictunStream* stream, ConnectingClientSocket* socket,
                             QuictunIdleTracker* idle_tracker,
                             std::function<void()> on_closed)
    : stream_(stream),
      socket_(socket),
      on_closed_(std::move(on_closed)),
      idle_tracker_(idle_tracker) {
  QUICHE_DCHECK(idle_tracker_ != nullptr);
}

QuictunTunnel::~QuictunTunnel() {
  // Contract, not cleanup: see idle_tracker_'s comment in the header. A
  // tunnel still linked here was destroyed without Close() ever running,
  // which also means its socket was never Disconnect()ed and its owner was
  // never notified -- deliberately not papered over by unlinking here,
  // since that would let the far larger problem ship silently.
  QUICHE_DCHECK(!quiche::QuicheIntrusiveList<QuictunTunnel>::is_linked(this));
}

void QuictunTunnel::SetSocket(ConnectingClientSocket* socket) {
  QUICHE_DCHECK(socket_ == nullptr) << "SetSocket() called more than once";
  QUICHE_DCHECK(socket != nullptr);
  socket_ = socket;
}

void QuictunTunnel::Start(absl::string_view seed_quic_to_tcp_data) {
  started_ = true;
  if (!seed_quic_to_tcp_data.empty()) {
    pending_to_tcp_.push_back(std::string(seed_quic_to_tcp_data));
  }
  NoteActivity();
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

void QuictunTunnel::OnStreamDataAvailable(QuicStreamId /*id*/) {
  if (closed_ || !started_) {
    // !started_: real repro, real crash -- on the server, this tunnel
    // becomes stream_'s active delegate (StartTunnelForStream()) before
    // the --target dial-out it's also the AsyncVisitor for has actually
    // finished connecting (a real async operation, can take real time --
    // see the class comment). If the peer sends more stream data before
    // that dial-out's ConnectComplete() fires Start(), this fires first:
    // MaybeFlushQuicToTcp() below only checks `socket_ == nullptr` to
    // decide whether it's safe to use socket_ -- true for the client
    // (whose socket_, once non-null, is by construction already
    // connected -- see the constructor's comment) but *not* true here,
    // where socket_ is set (SetSocket()) well before it's actually
    // connected. Confirmed via a real repro (killing the server
    // mid-restart under sustained connection churn) that falling through
    // crashes on a QUICHE_CHECK in
    // EventLoopConnectingClientSocket::SendInternal()
    // (connect_status_ == ConnectStatus::kConnected). Safe to just wait:
    // Start()'s own FillQueueFromStream() call (see its comment) already
    // catches up on anything that arrived in this window, exactly the
    // same way it already does for data that arrives even earlier, before
    // this tunnel exists as stream_'s delegate at all.
    return;
  }
  FillQueueFromStream();
  MaybeFlushQuicToTcp();
}

void QuictunTunnel::OnStreamCanWriteMore(QuicStreamId /*id*/) {
  if (closed_ || !started_) {
    // !started_: same reasoning as OnStreamDataAvailable()'s identical
    // check -- this can also reach BeginReadFromTcp() below, which has
    // the same socket_==nullptr-isn't-enough gap on the server side.
    // Nothing to catch up on here the way Start()'s own
    // FillQueueFromStream() call does for OnStreamDataAvailable(): once
    // Start() actually runs, BeginReadFromTcp()/MaybeFlushQuicToTcp()
    // (called from Start() itself) pick up wherever things stand from
    // scratch.
    return;
  }
  if (tcp_receive_done_) {
    // More write capacity freeing up is a reasonable proxy for "some
    // previously-sent data just got acked" -- an opportunistic early check,
    // cheaper than waiting out flush_close_alarm_'s full retry interval.
    MaybeFinalizeClose();
    return;
  }
  // Strict backpressure: only resume reading from the TCP side once every
  // previously-read byte has actually been handed off by the stream
  // (HasBufferedData() false), not just once there's *some* room (the old
  // CanBufferMoreWrites() check). This makes "we just read EOF" and "we
  // still have unsent data from a previous read" structurally mutually
  // exclusive, the way toggling a single read watcher on and off would --
  // see ReceiveComplete()'s empty-data branch, which no longer needs to
  // assume there might be unflushed data sitting around from a *previous*
  // read (flush_close_alarm_ still guards the *current*, just-written fin).
  //
  // A looser CanWriteNewData()-based check (QUICHE's own ~8KiB buffered_
  // data_threshold_, reused instead of this stricter "fully drained" rule)
  // was tried during a pooling stall investigation, on the
  // theory that this strict rule's higher re-enqueue churn was starving
  // other streams sharing a connection. It wasn't -- the stall's actual
  // cause turned out to be unrelated (see QuictunStreamDelegate::
  // OnStreamGone()'s comment in quictun_session.h) -- and the looser check
  // was reverted: ReceiveAsync() (quictun_accepted_tcp_socket.cc) isn't
  // purely event-driven, it calls back into ReceiveComplete() synchronously
  // inline whenever the kernel's TCP receive buffer already has data ready,
  // so BeginReadFromTcp() -> ReceiveComplete() -> BeginReadFromTcp() forms a
  // real synchronous recursion, not just a chain of event-loop turns. This
  // strict, harder-to-satisfy check breaks that recursion sooner (needs the
  // whole just-written chunk fully off the stream's own buffer, not just
  // under an 8KiB cushion); the looser one let it run measurably longer per
  // burst, on a low-RTT/high-throughput path more than this session's own
  // real-network testing exercised -- not worth the risk for a check that
  // was never actually fixing anything.
  UpdateIdleClass();
  if (tcp_receive_in_flight_ || stream_->HasBufferedData()) {
    return;
  }
  BeginReadFromTcp();
}

void QuictunTunnel::OnStreamGone(QuicStreamId /*id*/) {
  if (closed_) {
    return;
  }
  // The QUIC stream reached its natural end (FIN both ways acknowledged, or
  // a reset) on its own -- nothing left to forward in either direction, so
  // just release the TCP socket and let the owner tear the rest down.
  Close("stream closed", /*reset_stream=*/false);
}

void QuictunTunnel::ConnectComplete(absl::Status status) {
  // Client side: never invoked -- `socket_` (a QuictunAcceptedTcpSocket) is
  // already connected at construction and the owner calls Start() itself,
  // never ConnectAsync() on it. Server side (see the class/SetSocket()
  // comments): this is the completion callback for the owner's ConnectAsync()
  // dial-out to --target, kicked off after SetSocket() supplied the socket
  // this tunnel is registered as the AsyncVisitor of.
  if (closed_) {
    // Raced with the tunnel already being torn down some other way (e.g.
    // the QUIC stream closed while the dial-out was still in flight) --
    // Close() already disconnected socket_, nothing left to do here.
    return;
  }
  if (!status.ok()) {
    // A failed connect leaves the socket already closed: every path that
    // gets here -- ConnectAsync()'s own Open() failure, DoInitialConnect()'s
    // synchronous failure, GetConnectResult()'s asynchronous one -- either
    // never opened a descriptor or Close()d it and reset connect_status_ to
    // kNotConnected before calling back (see
    // event_loop_connecting_client_socket.cc). Disconnect()ing it now would
    // trip that class's own two entry DCHECKs, which is a real crash on a
    // debug build every time a --target refuses a connection, and a bogus
    // close(-1) plus a logged warning on a release one. QUICHE's own
    // consumers dodge this by never routing a failed connect into their
    // shared teardown at all (ConnectTunnel terminates the stream and
    // returns; masque_tcp_client_bin just logs and stops), which isn't an
    // option here -- everything else Close() does is still needed.
    socket_disconnected_ = true;
    Close("target connect failed", /*reset_stream=*/true);
    return;
  }
  Start(pending_seed_data_);
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
  NoteActivity();
  stream_->WriteToStream(data->AsStringView(), /*fin=*/false);
  // Strict backpressure -- see OnStreamCanWriteMore()'s comment: don't read
  // more until this write has fully drained, so a *later* EOF can never
  // land on top of still-unsent data from here.
  if (!stream_->HasBufferedData()) {
    BeginReadFromTcp();
  }
  // Otherwise wait for OnStreamCanWriteMore() to resume reading from TCP --
  // which is exactly the stalled state, hence the reclassification. It has
  // to happen here rather than inside the NoteActivity() above, which ran
  // before the write that created the backlog.
  UpdateIdleClass();
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
      NoteActivity();
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
  // Leaving the loop with the queue full means we stopped reading, so the
  // rest of the burst is now sitting in the stream's receive buffer holding
  // the connection's shared flow-control credit.
  UpdateIdleClass();
}

void QuictunTunnel::BeginReadFromTcp() {
  if (closed_ || tcp_receive_in_flight_ || tcp_receive_done_ ||
      socket_ == nullptr) {
    // socket_ == nullptr: still waiting on SetSocket()/ConnectComplete() on
    // the server path (see the class comment) -- nothing to read from yet.
    // Whichever of Start() or SetSocket() actually finishes that wait calls
    // this again.
    return;
  }
  tcp_receive_in_flight_ = true;
  socket_->ReceiveAsync(kReadSize);
}

void QuictunTunnel::MaybeFlushQuicToTcp() {
  if (closed_ || tcp_send_in_flight_ || socket_ == nullptr) {
    // socket_ == nullptr: same as BeginReadFromTcp() above -- whatever's
    // already in pending_to_tcp_ just stays queued until Start() runs (from
    // ConnectComplete()) and calls this again.
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
  // A slot just freed up, which may have taken this tunnel back out of the
  // stalled class. After SendAsync() rather than before, since it can call
  // back inline; UpdateIdleClass() is idempotent and guards on closed_.
  UpdateIdleClass();
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
                        << " (stream_id=" << stream_->id()
                        << ", HasBufferedData=" << stream_->HasBufferedData()
                        << ", IsWaitingForAcks=" << stream_->IsWaitingForAcks()
                        << ")";
    if (flush_close_alarm_) {
      flush_close_alarm_->Cancel();
    }
    // reset_stream=true, not false: unlike the clean-finish branch above,
    // this stream never actually finished -- HasBufferedData() is still
    // true here. Closing without a real QUIC-level Reset() would leave
    // this stream's already-sent-but-never-consumed bytes permanently
    // counted against this connection's session-level flow control
    // window -- nothing on either end ever tells the peer those bytes can
    // be released, because a clean FIN never completed and no RST_STREAM
    // was ever sent either. Real QUICHE's QuicStream::OnStreamReset() has
    // the peer advance its flow control to the RST frame's Final Size
    // field the moment it arrives, even though it never got (and now
    // never will get) the rest of the data -- freeing the corresponding
    // session-level window on this end once the peer's resulting
    // WINDOW_UPDATE arrives, exactly the mechanism IETF QUIC's RST_STREAM
    // Final Size field exists for. (smux, kcptun's own mux layer, enforces
    // the identical invariant from a different angle: Stream.Close()
    // synchronously calls session.streamClosed(), which immediately
    // returns that stream's still-held tokens to the session's shared
    // bucket -- a stream ending and the session-level resources it held
    // are never allowed to disagree about the stream's fate, in either
    // implementation.) This is a real, independent correctness fix worth
    // keeping on its own merits -- but investigation later showed it is
    // NOT what was causing a separate, reproduced pooling
    // stall (some streams on a shared connection permanently starved of
    // write opportunities while the connection's own session-level flow
    // control and congestion window both stayed healthy). That stall's
    // actual cause was a QuictunSessionBase::OnStreamClosed(QuicStreamId)
    // silently colliding with, and shadowing, QuicSession's own unrelated
    // same-signature virtual of the same name -- see
    // QuictunStreamDelegate::OnStreamGone()'s comment in quictun_session.h
    // for the full story and the actual fix.
    Close("tunnel finished (flush wait exceeded)", /*reset_stream=*/true);
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

void QuictunTunnel::NoteActivity() {
  // Load-bearing, and for a different reason than it used to be. It once
  // only avoided pointlessly re-arming a timer on a tunnel that was already
  // done; now it is what keeps a late callback -- one that lands after
  // Close() has already unlinked this tunnel -- from splicing an
  // about-to-be-destroyed object back into idle_tracker_, where the next
  // sweep would find a dangling pointer. Nothing else guards that: unlike
  // "destroyed without Close()", which shows up immediately as a leaked fd
  // (~QuictunAcceptedTcpSocket() asserts on exactly that), a re-linked
  // closed tunnel leaves the fd accounting perfectly clean.
  if (closed_) {
    return;
  }
  last_activity_ = stream_->connection()->clock()->ApproximateNow();
  stalled_ = IsHoldingBuffer();
  idle_tracker_->Touch(this, stalled_);
}

bool QuictunTunnel::IsHoldingBuffer() const {
  return pending_to_tcp_.size() >= kMaxQueuedChunks ||
         stream_->HasBufferedData();
}

void QuictunTunnel::UpdateIdleClass() {
  // Same closed_ guard, and load-bearing for the same reason, as
  // NoteActivity()'s: a late callback must not splice an already-unlinked
  // tunnel back into idle_tracker_.
  if (closed_) {
    return;
  }
  const bool stalled = IsHoldingBuffer();
  if (stalled == stalled_) {
    return;
  }
  stalled_ = stalled;
  // Both lists are sorted only by construction, so joining one at anything
  // but "now" appends an entry older than the tail and the sweep, which
  // only ever looks at the front, then reaps it late. Honest rather than a
  // way of dodging the deadline -- every flip of IsHoldingBuffer() is
  // itself real data movement (a chunk handed to the TCP socket, or the
  // stream's send buffer draining onto the wire), which is exactly what
  // last_activity_ records.
  last_activity_ = stream_->connection()->clock()->ApproximateNow();
  idle_tracker_->Refile(this, stalled_);
}

void QuictunTunnel::Close(absl::string_view reason, bool reset_stream) {
  QUICHE_DCHECK(!closed_);
  closed_ = true;
  if (flush_close_alarm_) {
    flush_close_alarm_->Cancel();
  }
  // Before anything below can reenter -- on_closed_() in particular hands
  // this tunnel to its owner, which may close siblings that reach back in
  // here. See idle_tracker_'s comment: this is the one and only unlink
  // site.
  idle_tracker_->Remove(this);
  QUICHE_LOG(INFO) << "Closing quictun tunnel: " << reason
                   << ", reset_stream=" << reset_stream;
  // Tell the sequencer to give up on any not-yet-Read() bytes it's still
  // holding for this stream, whichever way this Close() is happening --
  // mirrors real QUICHE's own pattern for abandoning a stream early (e.g.
  // QuicSimpleServerStream::SendErrorResponse(): "if (!reading_stopped())
  // StopReading();" before closing). Without this, those buffered-but-
  // unread bytes are never counted as consumed
  // (QuicStreamSequencer::FlushBufferedFrames(), only reachable via
  // StopReading(), is the only path that calls QuicStream::
  // AddBytesConsumed() for data the application itself never actually
  // Read() -- plain CloseReadSide(), which is all Reset() below triggers
  // on its own, only ReleaseBuffer()s the memory, without ever advancing
  // that accounting) -- permanently starving this connection's own
  // session-level flow control of the credit those bytes represent, since
  // nothing ever tells the peer they can stop being counted against it.
  // A real, independent correctness fix worth keeping on its own merits
  // (see the reset_stream=true comment above for the matching send-side
  // half of the same invariant) -- but not, per later investigation, what
  // was causing a separate, reproduced pooling stall; see that
  // comment for where the actual cause -- and fix -- ended up being.
  // Harmless to call unconditionally here (covers the reset_stream=false
  // paths too, e.g. TCP-side errors that still leave unread QUIC-side data
  // sitting in the sequencer): a no-op if this stream already finished
  // reading (FlushBufferedFrames() flushes zero bytes), and StopReading()
  // itself is purely local bookkeeping, not a network write, so it doesn't
  // need connection()->connected() guarding the way stream_->Reset() below
  // does.
  if (!stream_->reading_stopped()) {
    stream_->StopReading();
  }
  // socket_ can still be null here on the server path (see the constructor/
  // SetSocket()'s comments): a tunnel can close for reasons unrelated to the
  // target dial-out (e.g. the QUIC stream itself resetting) before that
  // dial-out was ever wired in. HasSocket() lets the owner's on_closed
  // callback know it still needs to disconnect its own copy in that case --
  // see that callback's comment. Same guarded shape as the owner's own
  // QuictunServerConnection::DisconnectStreamTarget(), one level down; see
  // socket_disconnected_ for the case that actually needs it.
  if (socket_ != nullptr && !socket_disconnected_) {
    socket_disconnected_ = true;
    socket_->Disconnect();
  }

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
