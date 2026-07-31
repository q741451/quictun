// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quictun/session_visitors.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quictun/tcp_util.h"
#include "quiche/quictun/tunnel_pump.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/web_transport/web_transport.h"

namespace quictun {

void ClientTunnelSessionVisitor::OnSessionClosed(
    webtransport::SessionErrorCode /*error_code*/,
    const std::string& error_message) {
  ready_ = false;
  closed_ = true;
  QUICHE_LOG(INFO) << "quictun session closed: " << error_message;
}

void ClientTunnelSessionVisitor::OnIncomingBidirectionalStreamAvailable() {
  while (webtransport::Stream* stream =
             session_->AcceptIncomingBidirectionalStream()) {
    stream->ResetWithUserCode(0);
  }
}

void ClientTunnelSessionVisitor::OnIncomingUnidirectionalStreamAvailable() {
  while (webtransport::Stream* stream =
             session_->AcceptIncomingUnidirectionalStream()) {
    stream->ResetWithUserCode(0);
  }
}

ServerTunnelSessionVisitor::ServerTunnelSessionVisitor(
    webtransport::Session* session, quic::QuicEventLoop* event_loop,
    quic::QuicSocketAddress target, bool quiet)
    : session_(session),
      event_loop_(event_loop),
      target_(target),
      quiet_(quiet) {}

void ServerTunnelSessionVisitor::OnSessionReady() {
  if (!quiet_) {
    QUICHE_LOG(INFO) << "quictun session established";
  }
}

void ServerTunnelSessionVisitor::OnSessionClosed(
    webtransport::SessionErrorCode /*error_code*/,
    const std::string& error_message) {
  if (!quiet_) {
    QUICHE_LOG(INFO) << "quictun session closed: " << error_message;
  }
}

void ServerTunnelSessionVisitor::OnIncomingBidirectionalStreamAvailable() {
  while (webtransport::Stream* stream =
             session_->AcceptIncomingBidirectionalStream()) {
    DialAndPump(stream);
  }
}

void ServerTunnelSessionVisitor::OnIncomingUnidirectionalStreamAvailable() {
  while (webtransport::Stream* stream =
             session_->AcceptIncomingUnidirectionalStream()) {
    stream->ResetWithUserCode(0);
  }
}

void ServerTunnelSessionVisitor::DialAndPump(webtransport::Stream* stream) {
  bool connecting = false;
  absl::StatusOr<quic::SocketFd> fd = ConnectNonBlocking(target_, &connecting);
  if (!fd.ok()) {
    if (!quiet_) {
      QUICHE_LOG(INFO) << "failed to dial target: " << fd.status();
    }
    stream->ResetWithUserCode(0);
    return;
  }
  if (!quiet_) {
    QUICHE_LOG(INFO) << "stream opened";
  }
  auto pump = std::make_unique<TunnelPump>(event_loop_, *fd, stream, quiet_,
                                           connecting);
  stream->SetVisitor(std::move(pump));
  // The stream may already carry data buffered before we attached a
  // visitor to it; give it a chance to drain, matching the pattern used by
  // quiche's own EchoWebTransportSessionVisitor.
  stream->visitor()->OnCanRead();
}

}  // namespace quictun
