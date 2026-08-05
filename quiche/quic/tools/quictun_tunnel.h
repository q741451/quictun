// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Pumps bytes between one QuictunStream and one ConnectingClientSocket. Used
// symmetrically by both binaries: quictun_server plugs in a real
// EventLoopConnectingClientSocket dialing --target; quictun_client plugs in
// a QuictunAcceptedTcpSocket wrapping an already-accepted --local
// connection.
//
// Deliberately fully async in both directions (SendAsync/ReceiveAsync only,
// never the *Blocking calls) -- unlike quic/tools/connect_tunnel.cc, whose
// blocking calls are safe there because each HTTP/3 CONNECT tunnel only ever
// blocks its own single QUIC connection's processing. quictun instead runs
// many concurrent tunnels on one shared event-loop thread (one per QUIC
// connection, see quictun_client_driver.h / quictun_server_driver.h), so a
// blocking call here would stall every other tunnel in the process.

#ifndef QUICHE_QUIC_TOOLS_QUICTUN_TUNNEL_H_
#define QUICHE_QUIC_TOOLS_QUICTUN_TUNNEL_H_

#include <deque>
#include <functional>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/connecting_client_socket.h"
#include "quiche/quic/tools/quictun_session.h"
#include "quiche/common/quiche_mem_slice.h"

namespace quic {

class QUICHE_EXPORT QuictunTunnel : public ConnectingClientSocket::AsyncVisitor,
                                    public QuictunStreamDelegate {
 public:
  // `stream` and `socket` must outlive this tunnel; the owning connection
  // object (QuictunClientConnection / QuictunServerConnection) is
  // responsible for that, and for destroying all three together. `on_closed`
  // is invoked (at most once) when the tunnel shuts down for any reason
  // (either side closing, or an I/O error) -- the owner should tear down the
  // whole connection (including the QUIC session/connection) in response.
  QuictunTunnel(QuictunStream* stream, ConnectingClientSocket* socket,
               std::function<void()> on_closed);

  // Begins pumping in both directions. `stream` must already be open and
  // `socket` must already be connected (the tunnel never itself calls
  // Connect{Blocking,Async}() on the socket). `seed_quic_to_tcp_data`, if
  // non-empty, is queued as already-received QUIC->TCP data before pumping
  // starts -- used by the server side, which reads and validates the
  // client's key preamble itself before constructing the tunnel, and may
  // have already read past the preamble into real payload bytes in the same
  // Read() call (see quictun_server_connection.cc).
  void Start(absl::string_view seed_quic_to_tcp_data = "");

  // QuictunStreamDelegate (QUIC -> TCP direction):
  void OnStreamDataAvailable() override;
  void OnStreamCanWriteMore() override;
  void OnStreamClosed() override;

  // ConnectingClientSocket::AsyncVisitor (TCP -> QUIC direction):
  void ConnectComplete(absl::Status status) override;
  void ReceiveComplete(absl::StatusOr<quiche::QuicheMemSlice> data) override;
  void SendComplete(absl::Status status) override;

 private:
  void BeginReadFromTcp();
  void MaybeFlushQuicToTcp();
  void Close(absl::string_view reason, bool reset_stream);

  QuictunStream* const stream_;
  ConnectingClientSocket* const socket_;
  std::function<void()> on_closed_;

  // Backpressure queue for QUIC->TCP bytes: QuictunStream::OnDataAvailable
  // is a synchronous callback (it must call Read() promptly to keep the QUIC
  // stream's flow control moving), but the TCP socket can only have one
  // SendAsync in flight at a time -- so reads that arrive while a send is
  // still in flight are queued here, up to kMaxQueuedChunks. Once the queue
  // is full, OnStreamDataAvailable stops calling Read() until it drains,
  // which lets unread bytes accumulate in the QUIC stream's own receive
  // buffer (bounded by its flow-control window) instead -- naturally
  // throttling the QUIC sender without needing any extra signaling.
  std::deque<std::string> pending_to_tcp_;
  bool tcp_send_in_flight_ = false;
  bool tcp_receive_in_flight_ = false;
  bool tcp_receive_done_ = false;
  bool closed_ = false;

  static constexpr size_t kReadSize = 16 * 1024;
  static constexpr size_t kMaxQueuedChunks = 4;
};

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_TUNNEL_H_
