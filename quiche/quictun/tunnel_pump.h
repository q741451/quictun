// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUICTUN_TUNNEL_PUMP_H_
#define QUICHE_QUICTUN_TUNNEL_PUMP_H_

#include <string>

#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/web_transport/web_transport.h"

namespace quictun {

// Pumps bytes bidirectionally between a plain TCP socket and a WebTransport
// bidirectional stream. This is the quictun equivalent of kcptun's
// handleClient()/streamCopy(): one TunnelPump == one proxied TCP connection.
//
// Ownership: a TunnelPump is handed to the stream via
// `stream->SetVisitor(std::unique_ptr<TunnelPump>(...))`, so its lifetime is
// tied to the underlying QUIC stream object exactly like quiche's own
// WebTransportBidirectionalEchoVisitor. Do not delete it manually and do not
// touch `stream_` from the destructor -- if we are being destroyed, it is
// because the owning Stream's own destructor triggered it, so the Stream may
// already be in a partially-torn-down state.
//
// Close semantics deliberately match kcptun: as soon as either direction
// hits EOF/error/FIN, the whole pump closes (no half-closed TCP support),
// mirroring kcptun's `select { case <-streamCopy(a,b): case
// <-streamCopy(b,a): }` followed by closing both ends unconditionally.
class TunnelPump : public quic::QuicSocketEventListener,
                   public webtransport::StreamVisitor {
 public:
  // If `connecting` is true, `tcp_fd` is a socket for which a non-blocking
  // connect() is already in flight (used on the server side while dialing
  // the proxied target); the first writable event will check
  // socket_api::GetSocketError() before treating the connection as usable.
  TunnelPump(quic::QuicEventLoop* event_loop, quic::SocketFd tcp_fd,
             webtransport::Stream* stream, bool quiet, bool connecting);
  ~TunnelPump() override;

  TunnelPump(const TunnelPump&) = delete;
  TunnelPump& operator=(const TunnelPump&) = delete;

  // quic::QuicSocketEventListener implementation (events on the TCP fd).
  void OnSocketEvent(quic::QuicEventLoop* event_loop, quic::SocketFd fd,
                     quic::QuicSocketEventMask events) override;

  // webtransport::StreamVisitor implementation.
  void OnCanRead() override;
  void OnCanWrite() override;
  void OnResetStreamReceived(webtransport::StreamErrorCode error) override;
  void OnStopSendingReceived(webtransport::StreamErrorCode error) override;
  void OnWriteSideInDataRecvdState() override {}

 private:
  void PumpSocketToStream();   // TCP socket -> WebTransport stream.
  void PumpStreamToSocket();   // WebTransport stream -> TCP socket.
  bool FlushPendingToSocket();  // Returns true iff pending_to_socket_ drained.
  quic::QuicSocketEventMask DesiredMask() const;
  void RearmInterest();
  void CloseAll();  // Idempotent: resets the stream, closes the TCP fd.

  quic::QuicEventLoop* event_loop_;
  quic::SocketFd tcp_fd_;
  webtransport::Stream* stream_;  // Not owned; see class comment.
  bool quiet_;
  bool connecting_;

  // Data read from the stream but not yet fully written to the TCP socket.
  std::string pending_to_socket_;

  quic::QuicSocketEventMask registered_mask_ = 0;
  bool closed_ = false;
};

}  // namespace quictun

#endif  // QUICHE_QUICTUN_TUNNEL_PUMP_H_
