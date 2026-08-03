// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUICTUN_SESSION_VISITORS_H_
#define QUICHE_QUICTUN_SESSION_VISITORS_H_

#include <string>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quictun/tunnel_pump.h"
#include "quiche/web_transport/web_transport.h"

namespace quictun {

// The client side owns one persistent WebTransport session per quictun
// "conn" (see kcptun's --conn); a new local TCP connection opens a stream
// on whichever session is ready(). quictun-client never expects the server
// to push streams to it, so any incoming stream is refused.
class ClientTunnelSessionVisitor : public webtransport::SessionVisitor {
 public:
  explicit ClientTunnelSessionVisitor(webtransport::Session* session)
      : session_(session) {}

  void OnSessionReady() override { ready_ = true; }
  void OnSessionClosed(webtransport::SessionErrorCode error_code,
                       const std::string& error_message) override;
  void OnIncomingBidirectionalStreamAvailable() override;
  void OnIncomingUnidirectionalStreamAvailable() override;
  void OnDatagramReceived(absl::string_view /*datagram*/) override {}
  void OnCanCreateNewOutgoingBidirectionalStream() override {}
  void OnCanCreateNewOutgoingUnidirectionalStream() override {}

  bool ready() const { return ready_; }
  bool closed() const { return closed_; }
  webtransport::Session* session() const { return session_; }

 private:
  webtransport::Session* session_;
  bool ready_ = false;
  bool closed_ = false;
};

// The server side owns one instance per accepted QUIC/WebTransport session;
// every incoming bidirectional stream carries an 8-byte TunnelId header
// (see tunnel_id.h) identifying which proxied TCP connection it belongs to.
// A new id dials `target` and registers a fresh TunnelPump in `registry`
// (shared across every session, not just this one -- autoexpire rotation
// on the client re-homes a tunnel onto a brand new QUIC connection, which
// shows up here as a stream on a completely different
// ServerTunnelSessionVisitor instance); an id already in `registry` is a
// rotation continuation, and just gets attached to its existing TunnelPump.
// Mirrors kcptun server's handleMux(), plus the continuation logic.
class ServerTunnelSessionVisitor : public webtransport::SessionVisitor {
 public:
  ServerTunnelSessionVisitor(webtransport::Session* session,
                             quic::QuicEventLoop* event_loop,
                             quic::QuicSocketAddress target, bool quiet,
                             TunnelRegistry* registry);

  void OnSessionReady() override;
  void OnSessionClosed(webtransport::SessionErrorCode error_code,
                       const std::string& error_message) override;
  void OnIncomingBidirectionalStreamAvailable() override;
  void OnIncomingUnidirectionalStreamAvailable() override;
  void OnDatagramReceived(absl::string_view /*datagram*/) override {}
  void OnCanCreateNewOutgoingBidirectionalStream() override {}
  void OnCanCreateNewOutgoingUnidirectionalStream() override {}

 private:
  webtransport::Session* session_;
  quic::QuicEventLoop* event_loop_;
  quic::QuicSocketAddress target_;
  bool quiet_;
  TunnelRegistry* registry_;
};

}  // namespace quictun

#endif  // QUICHE_QUICTUN_SESSION_VISITORS_H_
