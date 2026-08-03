// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quictun/tunnel_pump.h"

#include <algorithm>
#include <cstddef>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quictun/tunnel_id.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_mem_slice.h"
#include "quiche/web_transport/web_transport.h"

namespace quictun {

using ::quic::QuicEventLoop;
using ::quic::QuicSocketEventMask;
using ::quic::SocketFd;
using ::quic::kInvalidSocketFd;
using ::quic::kSocketEventError;
using ::quic::kSocketEventReadable;
using ::quic::kSocketEventWritable;
namespace socket_api = ::quic::socket_api;

namespace {
constexpr size_t kReadChunkSize = 64 * 1024;
// Bound on bytes forwarded from the TCP socket in a single event-loop
// callback, so one very chatty connection cannot starve the others sharing
// the event loop.
constexpr size_t kMaxBytesPerSocketPump = 256 * 1024;
}  // namespace

// --- StreamAdapter -----------------------------------------------------

StreamAdapter::~StreamAdapter() {
  if (parent_ != nullptr) {
    parent_->OnStreamGone(this);
  }
}

void StreamAdapter::OnCanRead() {
  if (parent_ != nullptr) {
    parent_->OnStreamCanRead(this);
  }
}

void StreamAdapter::OnCanWrite() {
  if (parent_ != nullptr) {
    parent_->OnStreamCanWrite(this);
  }
}

void StreamAdapter::OnResetStreamReceived(
    webtransport::StreamErrorCode /*error*/) {
  if (parent_ != nullptr) {
    parent_->OnStreamAborted(this);
  }
}

void StreamAdapter::OnStopSendingReceived(
    webtransport::StreamErrorCode /*error*/) {
  if (parent_ != nullptr) {
    parent_->OnStreamAborted(this);
  }
}

// --- TunnelPump ----------------------------------------------------------

TunnelPump::TunnelPump(QuicEventLoop* event_loop, SocketFd tcp_fd,
                       bool quiet, bool connecting, TunnelId id)
    : event_loop_(event_loop),
      tcp_fd_(tcp_fd),
      quiet_(quiet),
      connecting_(connecting),
      id_(id) {
  RearmInterest();
}

TunnelPump::~TunnelPump() {
  // By the time a TunnelPump is actually destroyed (via
  // TunnelRegistry::SweepClosed(), never any other way -- see the class
  // comment), CloseAll() has already run, so tcp_fd_ is already invalid;
  // this is just a defensive fallback.
  if (tcp_fd_ != kInvalidSocketFd) {
    event_loop_->UnregisterSocket(tcp_fd_);
    socket_api::Close(tcp_fd_);
    tcp_fd_ = kInvalidSocketFd;
  }
}

void TunnelPump::AttachStream(webtransport::Stream* stream, bool client_side,
                              absl::string_view initial_payload) {
  if (closed_) {
    stream->ResetWithUserCode(0);
    return;
  }
  // Copy this out before SetVisitor() below: on the server-side
  // continuation path, `initial_payload` is a view into the
  // soon-to-be-destroyed TunnelHeaderReader's own buffer (it is the caller,
  // currently executing inside that object's OnCanRead()) -- SetVisitor()
  // replaces and destroys it, which would otherwise leave `initial_payload`
  // dangling before it's ever read.
  std::string seed(initial_payload);
  auto adapter = std::make_unique<StreamAdapter>(this, stream);
  StreamAdapter* adapter_ptr = adapter.get();
  stream->SetVisitor(std::move(adapter));
  live_adapters_.push_back(adapter_ptr);

  if (client_side) {
    std::string header;
    AppendTunnelId(id_, &header);
    quiche::QuicheMemSlice slice = quiche::QuicheMemSlice::Copy(header);
    absl::Status status = stream->Writev(
        absl::MakeSpan(&slice, 1), webtransport::kDefaultStreamWriteOptions);
    if (!status.ok()) {
      CloseAll();
      return;
    }
  }

  if (write_stream_ != nullptr) {
    // A rotation: no more application data will ever be written to the
    // stream we're moving away from. SendFin() -- not ResetWithUserCode()
    // -- lets QUIC keep delivering whatever it already has buffered for
    // that stream, and lets the peer's read_queue_ advance past it as
    // soon as that FIN actually arrives, without requiring either side to
    // wait for the old connection to be torn down (which can take a long
    // time to even be detected -- see CheckSessionReplacements() in
    // quictun_client_bin.cc).
    write_stream_->SendFin();
  }
  write_stream_ = stream;
  read_queue_.push_back(PendingRead{stream, std::move(seed)});

  // The stream may already have data buffered -- e.g. it arrived in the
  // same flight as the header, or (server-side continuation) was queued up
  // while TunnelHeaderReader was still figuring out which tunnel this
  // belongs to -- so give it an immediate chance to drain instead of
  // waiting for the next natural OnCanRead().
  adapter_ptr->OnCanRead();
  if (!closed_) {
    RearmInterest();
  }
}

void TunnelPump::ForgetAdapter(StreamAdapter* adapter) {
  auto it = std::find(live_adapters_.begin(), live_adapters_.end(), adapter);
  if (it != live_adapters_.end()) {
    live_adapters_.erase(it);
  }
  webtransport::Stream* stream = adapter->stream();
  for (auto qit = read_queue_.begin(); qit != read_queue_.end(); ++qit) {
    if (qit->stream == stream) {
      read_queue_.erase(qit);
      break;
    }
  }
}

void TunnelPump::OnStreamAborted(StreamAdapter* adapter) {
  bool was_write_stream = (adapter->stream() == write_stream_);
  adapter->Detach();
  ForgetAdapter(adapter);
  if (was_write_stream) {
    write_stream_ = nullptr;
    CloseAll();
    return;
  }
  RearmInterest();
}

void TunnelPump::OnStreamGone(StreamAdapter* adapter) {
  bool was_write_stream = (adapter->stream() == write_stream_);
  ForgetAdapter(adapter);
  if (was_write_stream) {
    write_stream_ = nullptr;
    CloseAll();
    return;
  }
  RearmInterest();
}

void TunnelPump::OnStreamCanRead(StreamAdapter* /*adapter*/) {
  if (closed_) return;
  PumpStreamToSocket();
  RearmInterest();
}

void TunnelPump::OnStreamCanWrite(StreamAdapter* /*adapter*/) {
  if (closed_) return;
  PumpSocketToStream();
  RearmInterest();
}

void TunnelPump::CloseAll(bool graceful) {
  if (closed_) return;
  closed_ = true;
  if (!quiet_) {
    QUICHE_LOG(INFO) << "tunnel stream closed";
  }
  // Detach every adapter before touching any stream: resetting a stream can
  // synchronously destroy it (and its visitor), which would otherwise
  // reenter OnStreamGone() while we are still iterating here. Detach()
  // makes any such reentrant callback a silent no-op instead.
  std::vector<StreamAdapter*> adapters = std::move(live_adapters_);
  live_adapters_.clear();
  for (StreamAdapter* adapter : adapters) {
    webtransport::Stream* stream = adapter->stream();
    adapter->Detach();
    // SendFin() lets QUIC keep delivering whatever was already Writev()'d
    // into this stream's send buffer via normal retransmission; only fall
    // back to an outright Reset() if that's not possible (SendFin()
    // failing) or this isn't the graceful-completion case at all.
    if (!(graceful && stream == write_stream_ && stream->SendFin())) {
      stream->ResetWithUserCode(0);
    }
  }
  read_queue_.clear();
  write_stream_ = nullptr;
  if (tcp_fd_ != kInvalidSocketFd) {
    event_loop_->UnregisterSocket(tcp_fd_);
    socket_api::Close(tcp_fd_);
    tcp_fd_ = kInvalidSocketFd;
  }
  registered_mask_ = 0;
}

QuicSocketEventMask TunnelPump::DesiredMask() const {
  if (closed_) return 0;
  QuicSocketEventMask mask = kSocketEventError;
  if (write_stream_ != nullptr && write_stream_->CanWrite()) {
    mask |= kSocketEventReadable;
  }
  if (!pending_to_socket_.empty() || connecting_) {
    mask |= kSocketEventWritable;
  }
  return mask;
}

void TunnelPump::RearmInterest() {
  if (tcp_fd_ == kInvalidSocketFd) return;
  QuicSocketEventMask mask = DesiredMask();
  if (event_loop_->SupportsEdgeTriggered()) {
    if (mask == registered_mask_) return;
    if (registered_mask_ != 0) {
      event_loop_->UnregisterSocket(tcp_fd_);
    }
    if (mask != 0) {
      event_loop_->RegisterSocket(tcp_fd_, mask, this);
    }
  } else {
    if (mask != 0) {
      if (registered_mask_ == 0) {
        event_loop_->RegisterSocket(tcp_fd_, mask, this);
      } else {
        event_loop_->RearmSocket(tcp_fd_, mask);
      }
    }
    // If mask == 0, the one-shot registration has already lapsed; there is
    // nothing to unregister.
  }
  registered_mask_ = mask;
}

void TunnelPump::OnSocketEvent(QuicEventLoop* /*event_loop*/, SocketFd /*fd*/,
                               QuicSocketEventMask events) {
  if (closed_) return;
  if (events & kSocketEventError) {
    if (!quiet_) {
      QUICHE_LOG(INFO) << "tunnel tcp socket error";
    }
    CloseAll();
    return;
  }
  if (events & kSocketEventWritable) {
    if (connecting_) {
      connecting_ = false;
      absl::Status err = socket_api::GetSocketError(tcp_fd_);
      if (!err.ok()) {
        if (!quiet_) {
          QUICHE_LOG(INFO) << "target connect failed: " << err;
        }
        CloseAll();
        return;
      }
      if (!quiet_) {
        QUICHE_LOG(INFO) << "stream opened";
      }
    }
    PumpStreamToSocket();
  }
  if (!closed_ && (events & kSocketEventReadable)) {
    PumpSocketToStream();
  }
  if (!closed_) {
    RearmInterest();
  }
}

void TunnelPump::PumpSocketToStream() {
  if (closed_ || write_stream_ == nullptr) return;
  char buf[kReadChunkSize];
  size_t total = 0;
  while (total < kMaxBytesPerSocketPump) {
    if (!write_stream_->CanWrite()) {
      return;  // Wait for OnCanWrite(); data stays buffered in the kernel.
    }
    absl::StatusOr<absl::Span<char>> received =
        socket_api::Receive(tcp_fd_, absl::MakeSpan(buf, sizeof(buf)));
    if (!received.ok()) {
      if (absl::IsUnavailable(received.status())) {
        return;  // Would block; nothing more to read right now.
      }
      CloseAll();
      return;
    }
    if (received->empty()) {
      // TCP EOF: match kcptun's close-both-on-first-EOF. Graceful: the
      // local side finished cleanly, not an error, so let write_stream_
      // finish delivering whatever it already has buffered.
      CloseAll(/*graceful=*/true);
      return;
    }
    quiche::QuicheMemSlice slice = quiche::QuicheMemSlice::Copy(
        absl::string_view(received->data(), received->size()));
    absl::Status status = write_stream_->Writev(
        absl::MakeSpan(&slice, 1), webtransport::kDefaultStreamWriteOptions);
    if (!status.ok()) {
      CloseAll();
      return;
    }
    total += received->size();
  }
}

void TunnelPump::PumpStreamToSocket() {
  if (closed_) return;
  if (!pending_to_socket_.empty() && !FlushPendingToSocket()) return;
  while (!closed_ && !read_queue_.empty()) {
    PendingRead& front = read_queue_.front();
    webtransport::Stream* front_stream = front.stream;
    if (!front.seed.empty()) {
      pending_to_socket_ = std::move(front.seed);
      front.seed.clear();
      if (!FlushPendingToSocket()) return;
      continue;
    }
    std::string buffer;
    webtransport::Stream::ReadResult result = front_stream->Read(&buffer);
    if (!buffer.empty()) {
      pending_to_socket_ = std::move(buffer);
      if (!FlushPendingToSocket()) return;  // Now blocked on the TCP write.
    }
    if (result.fin) {
      bool was_last_and_current = (front_stream == write_stream_);
      read_queue_.pop_front();
      if (was_last_and_current && read_queue_.empty()) {
        // The stream we're actively writing to also just finished reading
        // (FIN) with nothing queued behind it -- the peer closed their
        // side and there is no successor tunnel to fall back to; matches
        // the pre-rotation TunnelPump's fin-closes-everything behavior.
        // Graceful: the peer finished cleanly, not an error.
        CloseAll(/*graceful=*/true);
        return;
      }
      continue;
    }
    if (buffer.empty()) return;  // Nothing more available right now.
  }
}

bool TunnelPump::FlushPendingToSocket() {
  absl::StatusOr<absl::string_view> remainder =
      socket_api::Send(tcp_fd_, pending_to_socket_);
  if (!remainder.ok()) {
    if (absl::IsUnavailable(remainder.status())) {
      return false;  // Fully blocked; keep pending_to_socket_ as-is.
    }
    CloseAll();
    return false;
  }
  if (remainder->empty()) {
    pending_to_socket_.clear();
    return true;
  }
  // `*remainder` aliases into pending_to_socket_'s own buffer (it is the
  // unsent suffix of what was just passed to Send()), so copy it out into a
  // fresh string before overwriting pending_to_socket_ -- assigning in place
  // from a view of its own storage would be undefined behavior.
  std::string unsent(*remainder);
  pending_to_socket_ = std::move(unsent);
  return false;
}

}  // namespace quictun
