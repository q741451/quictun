// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_accepted_tcp_socket.h"

#include <limits>
#include <string>
#include <utility>
#include <variant>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/quiche_mem_slice.h"

namespace quic {

QuictunAcceptedTcpSocket::QuictunAcceptedTcpSocket(
    SocketFd fd, const QuicSocketAddress& peer_address,
    QuicEventLoop* event_loop, quiche::QuicheBufferAllocator* buffer_allocator,
    AsyncVisitor* async_visitor)
    : peer_address_(peer_address),
      event_loop_(event_loop),
      buffer_allocator_(buffer_allocator),
      async_visitor_(async_visitor),
      descriptor_(fd) {
  QUICHE_DCHECK_NE(descriptor_, kInvalidSocketFd);
  QUICHE_DCHECK(event_loop_);
  QUICHE_DCHECK(buffer_allocator_);

  // Same rationale as EventLoopConnectingClientSocket::Open(): register now,
  // with no events armed yet if the event loop isn't edge-triggered, so the
  // registration lifetime is simple (always spans [construction, Close())).
  bool registered;
  if (event_loop_->SupportsEdgeTriggered()) {
    registered = event_loop_->RegisterSocket(
        descriptor_,
        kSocketEventReadable | kSocketEventWritable | kSocketEventError,
        this);
  } else {
    registered = event_loop_->RegisterSocket(descriptor_, /*events=*/0, this);
  }
  QUICHE_DCHECK(registered);
}

QuictunAcceptedTcpSocket::~QuictunAcceptedTcpSocket() {
  QUICHE_DCHECK_EQ(descriptor_, kInvalidSocketFd)
      << "Must call Disconnect() before destruction.";
}

absl::Status QuictunAcceptedTcpSocket::ConnectBlocking() {
  return absl::OkStatus();
}

void QuictunAcceptedTcpSocket::ConnectAsync() {
  async_visitor_->ConnectComplete(absl::OkStatus());
}

void QuictunAcceptedTcpSocket::Disconnect() {
  if (descriptor_ == kInvalidSocketFd) {
    return;
  }
  Close();

  bool require_receive_callback = receive_max_size_.has_value();
  receive_max_size_.reset();
  bool require_send_callback = !std::holds_alternative<std::monostate>(send_data_);
  send_data_ = std::monostate();
  send_remaining_ = "";

  if (require_receive_callback) {
    async_visitor_->ReceiveComplete(absl::CancelledError());
  }
  if (require_send_callback) {
    async_visitor_->SendComplete(absl::CancelledError());
  }
}

absl::StatusOr<QuicSocketAddress> QuictunAcceptedTcpSocket::GetLocalAddress() {
  QUICHE_DCHECK_NE(descriptor_, kInvalidSocketFd);
  return socket_api::GetSocketAddress(descriptor_);
}

absl::StatusOr<quiche::QuicheMemSlice>
QuictunAcceptedTcpSocket::ReceiveBlocking(QuicByteCount max_size) {
  QUICHE_DCHECK_GT(max_size, 0u);
  QUICHE_DCHECK_NE(descriptor_, kInvalidSocketFd);
  QUICHE_DCHECK(!receive_max_size_.has_value());

  absl::Status status = socket_api::SetSocketBlocking(descriptor_, true);
  if (!status.ok()) {
    return status;
  }
  receive_max_size_ = max_size;
  absl::StatusOr<quiche::QuicheMemSlice> buffer = ReceiveInternal();
  if (!buffer.ok() && absl::IsUnavailable(buffer.status())) {
    receive_max_size_.reset();
  }
  absl::Status unblock_status =
      socket_api::SetSocketBlocking(descriptor_, false);
  if (!unblock_status.ok()) {
    return unblock_status;
  }
  return buffer;
}

void QuictunAcceptedTcpSocket::ReceiveAsync(QuicByteCount max_size) {
  QUICHE_DCHECK_GT(max_size, 0u);
  QUICHE_DCHECK_NE(descriptor_, kInvalidSocketFd);
  QUICHE_DCHECK(!receive_max_size_.has_value());

  receive_max_size_ = max_size;
  FinishOrRearmAsyncReceive(ReceiveInternal());
}

absl::Status QuictunAcceptedTcpSocket::SendBlocking(std::string data) {
  QUICHE_DCHECK(!data.empty());
  QUICHE_DCHECK(std::holds_alternative<std::monostate>(send_data_));

  absl::Status blocking_status = socket_api::SetSocketBlocking(descriptor_, true);
  if (!blocking_status.ok()) {
    return blocking_status;
  }
  send_data_ = std::move(data);
  send_remaining_ = std::get<std::string>(send_data_);
  absl::Status status;
  while (!send_remaining_.empty()) {
    status = SendInternal();
    if (!status.ok()) {
      break;
    }
  }
  send_data_ = std::monostate();
  send_remaining_ = "";
  absl::Status unblock_status =
      socket_api::SetSocketBlocking(descriptor_, false);
  return status.ok() ? unblock_status : status;
}

absl::Status QuictunAcceptedTcpSocket::SendBlocking(
    quiche::QuicheMemSlice data) {
  return SendBlocking(std::string(data.AsStringView()));
}

void QuictunAcceptedTcpSocket::SendAsync(std::string data) {
  QUICHE_DCHECK(!data.empty());
  QUICHE_DCHECK(std::holds_alternative<std::monostate>(send_data_));

  send_data_ = std::move(data);
  send_remaining_ = std::get<std::string>(send_data_);
  FinishOrRearmAsyncSend(SendInternal());
}

void QuictunAcceptedTcpSocket::SendAsync(quiche::QuicheMemSlice data) {
  QUICHE_DCHECK(!data.empty());
  QUICHE_DCHECK(std::holds_alternative<std::monostate>(send_data_));

  send_data_ = std::move(data);
  send_remaining_ = std::get<quiche::QuicheMemSlice>(send_data_).AsStringView();
  FinishOrRearmAsyncSend(SendInternal());
}

void QuictunAcceptedTcpSocket::OnSocketEvent(QuicEventLoop* event_loop,
                                             SocketFd fd,
                                             QuicSocketEventMask events) {
  QUICHE_DCHECK_EQ(event_loop, event_loop_);
  QUICHE_DCHECK_EQ(fd, descriptor_);

  if (receive_max_size_.has_value() &&
      (events & (kSocketEventReadable | kSocketEventError))) {
    FinishOrRearmAsyncReceive(ReceiveInternal());
  }
  if (!send_remaining_.empty() &&
      (events & (kSocketEventWritable | kSocketEventError))) {
    FinishOrRearmAsyncSend(SendInternal());
  }
}

absl::StatusOr<quiche::QuicheMemSlice>
QuictunAcceptedTcpSocket::ReceiveInternal() {
  QUICHE_CHECK(receive_max_size_.has_value());

  quiche::QuicheBuffer buffer(buffer_allocator_, *receive_max_size_);
  absl::StatusOr<absl::Span<char>> received = socket_api::Receive(
      descriptor_, absl::MakeSpan(buffer.data(), buffer.size()));
  if (received.ok()) {
    receive_max_size_.reset();
    return quiche::QuicheMemSlice(
        quiche::QuicheBuffer(buffer.Release(), received->size()));
  }
  if (!absl::IsUnavailable(received.status())) {
    receive_max_size_.reset();
  }
  return received.status();
}

void QuictunAcceptedTcpSocket::FinishOrRearmAsyncReceive(
    absl::StatusOr<quiche::QuicheMemSlice> data) {
  if (!data.ok() && absl::IsUnavailable(data.status())) {
    if (!event_loop_->SupportsEdgeTriggered()) {
      bool result = event_loop_->RearmSocket(
          descriptor_, kSocketEventReadable | kSocketEventError);
      QUICHE_DCHECK(result);
    }
    return;
  }
  async_visitor_->ReceiveComplete(std::move(data));
}

absl::Status QuictunAcceptedTcpSocket::SendInternal() {
  QUICHE_DCHECK(!send_remaining_.empty());

  absl::StatusOr<absl::string_view> result =
      socket_api::Send(descriptor_, send_remaining_);
  if (!result.ok()) {
    return result.status();
  }
  send_remaining_ = *result;
  return absl::OkStatus();
}

void QuictunAcceptedTcpSocket::FinishOrRearmAsyncSend(absl::Status status) {
  if (status.ok() && !send_remaining_.empty()) {
    // Partial send; more to go, but the socket accepted what it could.
    status = absl::UnavailableError("partial send");
  }
  if (absl::IsUnavailable(status)) {
    if (!event_loop_->SupportsEdgeTriggered()) {
      bool result = event_loop_->RearmSocket(
          descriptor_, kSocketEventWritable | kSocketEventError);
      QUICHE_DCHECK(result);
    }
    return;
  }
  send_data_ = std::monostate();
  send_remaining_ = "";
  async_visitor_->SendComplete(status);
}

void QuictunAcceptedTcpSocket::Close() {
  QUICHE_DCHECK_NE(descriptor_, kInvalidSocketFd);
  bool unregistered = event_loop_->UnregisterSocket(descriptor_);
  QUICHE_DCHECK(unregistered);
  absl::Status status = socket_api::Close(descriptor_);
  if (!status.ok()) {
    QUICHE_LOG(WARNING) << "Failed to close accepted TCP socket to "
                        << peer_address_ << ": " << status;
  }
  descriptor_ = kInvalidSocketFd;
}

}  // namespace quic
