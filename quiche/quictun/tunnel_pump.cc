// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quictun/tunnel_pump.h"

#include <cstddef>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/io/socket.h"
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

TunnelPump::TunnelPump(QuicEventLoop* event_loop, SocketFd tcp_fd,
                       webtransport::Stream* stream, bool quiet,
                       bool connecting)
    : event_loop_(event_loop),
      tcp_fd_(tcp_fd),
      stream_(stream),
      quiet_(quiet),
      connecting_(connecting) {
  RearmInterest();
}

TunnelPump::~TunnelPump() {
  // Do NOT touch `stream_` here: see the class comment in the header for why
  // this destructor may be running as part of the owning Stream's own
  // teardown.
  if (tcp_fd_ != kInvalidSocketFd) {
    event_loop_->UnregisterSocket(tcp_fd_);
    socket_api::Close(tcp_fd_);
    tcp_fd_ = kInvalidSocketFd;
  }
}

void TunnelPump::CloseAll() {
  if (closed_) return;
  closed_ = true;
  if (!quiet_) {
    QUICHE_LOG(INFO) << "tunnel stream closed";
  }
  if (stream_ != nullptr) {
    stream_->ResetWithUserCode(0);
    stream_ = nullptr;
  }
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
  if (stream_ != nullptr && stream_->CanWrite()) {
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
  RearmInterest();
}

void TunnelPump::OnCanRead() {
  if (closed_) return;
  PumpStreamToSocket();
  RearmInterest();
}

void TunnelPump::OnCanWrite() {
  if (closed_) return;
  PumpSocketToStream();
  RearmInterest();
}

void TunnelPump::OnResetStreamReceived(webtransport::StreamErrorCode /*error*/) {
  CloseAll();
}

void TunnelPump::OnStopSendingReceived(webtransport::StreamErrorCode /*error*/) {
  CloseAll();
}

void TunnelPump::PumpSocketToStream() {
  if (closed_ || stream_ == nullptr) return;
  char buf[kReadChunkSize];
  size_t total = 0;
  while (total < kMaxBytesPerSocketPump) {
    if (!stream_->CanWrite()) {
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
      CloseAll();  // TCP EOF: match kcptun's close-both-on-first-EOF.
      return;
    }
    quiche::QuicheMemSlice slice = quiche::QuicheMemSlice::Copy(
        absl::string_view(received->data(), received->size()));
    absl::Status status = stream_->Writev(
        absl::MakeSpan(&slice, 1), webtransport::kDefaultStreamWriteOptions);
    if (!status.ok()) {
      CloseAll();
      return;
    }
    total += received->size();
  }
}

void TunnelPump::PumpStreamToSocket() {
  if (closed_ || connecting_) return;  // Target connect() not finished yet.
  if (!pending_to_socket_.empty() && !FlushPendingToSocket()) return;
  if (stream_ == nullptr) return;
  while (!closed_) {
    std::string buffer;
    webtransport::Stream::ReadResult result = stream_->Read(&buffer);
    if (!buffer.empty()) {
      pending_to_socket_ = std::move(buffer);
      if (!FlushPendingToSocket()) return;  // Now blocked on the TCP write.
    }
    if (result.fin) {
      CloseAll();
      return;
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
