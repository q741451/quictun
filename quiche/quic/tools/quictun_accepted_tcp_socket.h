// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A ConnectingClientSocket that wraps an already-accept()ed, already-
// connected TCP file descriptor, so quictun_client's accepted --local
// connections can be driven by the same QuictunTunnel pump class that
// quictun_server uses for its (freshly dialed) EventLoopConnectingClientSocket
// connections to --target. Closely mirrors
// quiche/quic/core/io/event_loop_connecting_client_socket.{h,cc}'s async
// receive/send bookkeeping, minus the connect phase (there is none: the
// socket is connected from the moment it's constructed).

#ifndef QUICHE_QUIC_TOOLS_QUICTUN_ACCEPTED_TCP_SOCKET_H_
#define QUICHE_QUIC_TOOLS_QUICTUN_ACCEPTED_TCP_SOCKET_H_

#include <optional>
#include <string>
#include <variant>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/connecting_client_socket.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/quiche_mem_slice.h"

namespace quic {

class QUICHE_EXPORT QuictunAcceptedTcpSocket : public ConnectingClientSocket,
                                               public QuicSocketEventListener {
 public:
  // Takes ownership of `fd`, which must already be a connected, non-blocking
  // TCP socket (as returned by socket_api::Accept()). `event_loop` and
  // `buffer_allocator` must outlive this object. `async_visitor` may be
  // nullptr at construction and set later via SetAsyncVisitor() -- useful
  // when this socket and its visitor (typically a QuictunTunnel) need to be
  // constructed with pointers to each other -- but must be non-null before
  // any Receive/SendAsync call.
  QuictunAcceptedTcpSocket(SocketFd fd, const QuicSocketAddress& peer_address,
                           QuicEventLoop* event_loop,
                           quiche::QuicheBufferAllocator* buffer_allocator,
                           AsyncVisitor* async_visitor);

  ~QuictunAcceptedTcpSocket() override;

  void SetAsyncVisitor(AsyncVisitor* async_visitor) {
    async_visitor_ = async_visitor;
  }

  // ConnectingClientSocket. The socket is already connected as of
  // construction, so Connect{Blocking,Async}() below are trivially
  // successful no-ops; quictun's own code never calls them.
  absl::Status ConnectBlocking() override;
  void ConnectAsync() override;
  void Disconnect() override;
  absl::StatusOr<QuicSocketAddress> GetLocalAddress() override;
  absl::StatusOr<quiche::QuicheMemSlice> ReceiveBlocking(
      QuicByteCount max_size) override;
  void ReceiveAsync(QuicByteCount max_size) override;
  absl::Status SendBlocking(std::string data) override;
  absl::Status SendBlocking(quiche::QuicheMemSlice data) override;
  void SendAsync(std::string data) override;
  void SendAsync(quiche::QuicheMemSlice data) override;

  // QuicSocketEventListener:
  void OnSocketEvent(QuicEventLoop* event_loop, SocketFd fd,
                     QuicSocketEventMask events) override;

 private:
  absl::StatusOr<quiche::QuicheMemSlice> ReceiveInternal();
  void FinishOrRearmAsyncReceive(absl::StatusOr<quiche::QuicheMemSlice> data);
  absl::Status SendInternal();
  void FinishOrRearmAsyncSend(absl::Status status);
  void Close();

  const QuicSocketAddress peer_address_;
  QuicEventLoop* const event_loop_;                  // unowned
  quiche::QuicheBufferAllocator* buffer_allocator_;  // unowned
  AsyncVisitor* async_visitor_;                      // unowned

  SocketFd descriptor_;

  std::optional<QuicByteCount> receive_max_size_;
  std::variant<std::monostate, std::string, quiche::QuicheMemSlice>
      send_data_;
  absl::string_view send_remaining_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_ACCEPTED_TCP_SOCKET_H_
