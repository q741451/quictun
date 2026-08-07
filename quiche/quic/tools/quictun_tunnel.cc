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

// How long MaybeCloseAfterLocalEof() waits, total, for the stream to finish
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

}  // namespace

QuictunTunnel::QuictunTunnel(QuictunStream* stream, ConnectingClientSocket* socket,
                             std::function<void()> on_closed)
    : stream_(stream), socket_(socket), on_closed_(std::move(on_closed)) {}

void QuictunTunnel::Start(absl::string_view seed_quic_to_tcp_data) {
  if (!seed_quic_to_tcp_data.empty()) {
    pending_to_tcp_.push_back(std::string(seed_quic_to_tcp_data));
  }
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
    MaybeCloseAfterLocalEof();
    return;
  }
  if (tcp_receive_in_flight_) {
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
    // header). See MaybeCloseAfterLocalEof() for why this can't just close
    // immediately, though: see tcp_receive_done_'s comment.
    tcp_receive_done_ = true;
    local_eof_time_ = stream_->connection()->clock()->ApproximateNow();
    stream_->WriteToStream("", /*fin=*/true);
    MaybeCloseAfterLocalEof();
    return;
  }
  stream_->WriteToStream(data->AsStringView(), /*fin=*/false);
  if (stream_->CanBufferMoreWrites()) {
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
  // sending and we've forwarded everything it sent, so treat the tunnel as
  // finished rather than waiting on the TCP target to also decide to close
  // -- which, for a target that itself expects the client to hang up first,
  // may never happen (see the comment on quic_receive_done_ in the header).
  Close("peer finished sending, no more data to relay",
        /*reset_stream=*/false);
}

void QuictunTunnel::MaybeCloseAfterLocalEof() {
  if (closed_ || !tcp_receive_done_) {
    return;
  }
  if (!stream_->HasBufferedData() && !stream_->IsWaitingForAcks()) {
    if (flush_close_alarm_) {
      flush_close_alarm_->Cancel();
    }
    Close("TCP target closed connection", /*reset_stream=*/false);
    return;
  }
  QuicConnection* connection = stream_->connection();
  QuicTime now = connection->clock()->ApproximateNow();
  if (now - local_eof_time_ >= kMaxFlushCloseWait) {
    // Waited long enough -- either the peer is gone and nothing will ever
    // ack, or something else is stuck. Don't hang the tunnel open forever;
    // close anyway, same tradeoff idle_timeout makes at a coarser grain.
    QUICHE_DVLOG(1) << "Giving up waiting for stream flush after "
                    << kMaxFlushCloseWait << ", closing anyway";
    if (flush_close_alarm_) {
      flush_close_alarm_->Cancel();
    }
    Close("TCP target closed connection (flush wait exceeded)",
          /*reset_stream=*/false);
    return;
  }
  if (!flush_close_alarm_) {
    flush_close_alarm_.reset(
        connection->alarm_factory()->CreateAlarm(new FlushCloseAlarmDelegate(this)));
  }
  QuicTime deadline = std::min(now + kFlushCloseRetryInterval,
                               local_eof_time_ + kMaxFlushCloseWait);
  if (!flush_close_alarm_->IsSet() || flush_close_alarm_->deadline() > deadline) {
    flush_close_alarm_->Update(deadline, QuicTime::Delta::Zero());
  }
}

void QuictunTunnel::OnFlushCloseAlarm() { MaybeCloseAfterLocalEof(); }

void QuictunTunnel::Close(absl::string_view reason, bool reset_stream) {
  QUICHE_DCHECK(!closed_);
  closed_ = true;
  if (flush_close_alarm_) {
    flush_close_alarm_->Cancel();
  }
  QUICHE_DVLOG(1) << "Closing quictun tunnel: " << reason;
  socket_->Disconnect();
  if (reset_stream) {
    stream_->Reset(QUIC_STREAM_CANCELLED);
  }
  std::function<void()> on_closed = std::move(on_closed_);
  if (on_closed) {
    on_closed();
  }
}

}  // namespace quic
