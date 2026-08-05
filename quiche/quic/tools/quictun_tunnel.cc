// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_tunnel.h"

#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_mem_slice.h"

namespace quic {

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
  if (closed_ || tcp_receive_in_flight_ || tcp_receive_done_) {
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
    // TCP peer closed its write side: forward as a QUIC FIN. The TCP fd's
    // own read side is left alone (no `shutdown(SHUT_WR)` equivalent is
    // exposed by ConnectingClientSocket) -- data may still flow QUIC->TCP
    // until the stream fully closes; see the file comment for this known
    // limitation.
    tcp_receive_done_ = true;
    stream_->WriteToStream("", /*fin=*/true);
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
      // No more QUIC->TCP data will ever arrive; nothing else to do here
      // (the stream's own OnClose()/OnStreamClosed() is what eventually
      // tears the tunnel down once both directions are fully finished).
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
  if (closed_ || tcp_send_in_flight_ || pending_to_tcp_.empty()) {
    return;
  }
  std::string chunk = std::move(pending_to_tcp_.front());
  pending_to_tcp_.pop_front();
  tcp_send_in_flight_ = true;
  socket_->SendAsync(std::move(chunk));
}

void QuictunTunnel::Close(absl::string_view reason, bool reset_stream) {
  QUICHE_DCHECK(!closed_);
  closed_ = true;
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
