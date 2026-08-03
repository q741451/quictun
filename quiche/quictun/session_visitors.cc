// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quictun/session_visitors.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quictun/tcp_util.h"
#include "quiche/quictun/tunnel_id.h"
#include "quiche/quictun/tunnel_pump.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/web_transport/web_transport.h"

namespace quictun {
namespace {

// Reads the fixed-size TunnelId header off a newly-opened incoming stream
// before handing it off to the right TunnelPump: an existing one (rotation
// continuation) or a freshly created and registered one (brand new
// tunnel). This IS the stream's visitor until enough header bytes have
// arrived; TunnelPump::AttachStream() then replaces it (via
// Stream::SetVisitor), destroying this object -- see the note in
// OnCanRead() about not touching `this` afterwards, the same
// self-replacing-visitor pattern the old (pre-tunnel_id) DialAndPump used.
class TunnelHeaderReader : public webtransport::StreamVisitor {
 public:
  TunnelHeaderReader(webtransport::Stream* stream,
                     quic::QuicEventLoop* event_loop,
                     quic::QuicSocketAddress target, bool quiet,
                     TunnelRegistry* registry)
      : stream_(stream),
        event_loop_(event_loop),
        target_(target),
        quiet_(quiet),
        registry_(registry) {}

  void OnCanRead() override {
    while (buffer_.size() < kTunnelIdWireSize) {
      webtransport::Stream::ReadResult result = stream_->Read(&buffer_);
      if (buffer_.size() >= kTunnelIdWireSize) break;
      if (result.fin) {
        // Too short to ever contain a valid header; nothing more is coming.
        stream_->ResetWithUserCode(0);
        return;
      }
      if (result.bytes_read == 0) return;  // Nothing available right now.
    }
    std::optional<TunnelId> id = ParseTunnelId(buffer_);
    absl::string_view leftover(buffer_);
    leftover.remove_prefix(kTunnelIdWireSize);

    if (TunnelPump* pump = registry_->Find(*id); pump != nullptr) {
      // `this` is destroyed inside AttachStream() (it replaces the
      // stream's visitor); do not touch any member after this call.
      pump->AttachStream(stream_, /*client_side=*/false, leftover);
      return;
    }

    bool connecting = false;
    absl::StatusOr<quic::SocketFd> fd =
        ConnectNonBlocking(target_, &connecting);
    if (!fd.ok()) {
      if (!quiet_) {
        QUICHE_LOG(INFO) << "failed to dial target: " << fd.status();
      }
      stream_->ResetWithUserCode(0);
      return;
    }
    if (!quiet_) {
      QUICHE_LOG(INFO) << "stream opened";
    }
    auto new_pump = std::make_unique<TunnelPump>(event_loop_, *fd, quiet_,
                                                 connecting, *id);
    TunnelPump* new_pump_ptr = registry_->Register(*id, std::move(new_pump));
    // Same note as above: `this` is destroyed inside AttachStream().
    new_pump_ptr->AttachStream(stream_, /*client_side=*/false, leftover);
  }

  void OnCanWrite() override {}
  void OnResetStreamReceived(webtransport::StreamErrorCode /*error*/) override {
  }
  void OnStopSendingReceived(webtransport::StreamErrorCode /*error*/) override {
  }
  void OnWriteSideInDataRecvdState() override {}

 private:
  webtransport::Stream* stream_;
  quic::QuicEventLoop* event_loop_;
  quic::QuicSocketAddress target_;
  bool quiet_;
  TunnelRegistry* registry_;
  std::string buffer_;
};

}  // namespace

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
    quic::QuicSocketAddress target, bool quiet, TunnelRegistry* registry)
    : session_(session),
      event_loop_(event_loop),
      target_(target),
      quiet_(quiet),
      registry_(registry) {}

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
    auto reader = std::make_unique<TunnelHeaderReader>(
        stream, event_loop_, target_, quiet_, registry_);
    stream->SetVisitor(std::move(reader));
    // The stream may already carry data buffered before we attached a
    // visitor to it; give it a chance to drain, matching the pattern used by
    // quiche's own EchoWebTransportSessionVisitor.
    stream->visitor()->OnCanRead();
  }
}

void ServerTunnelSessionVisitor::OnIncomingUnidirectionalStreamAvailable() {
  while (webtransport::Stream* stream =
             session_->AcceptIncomingUnidirectionalStream()) {
    stream->ResetWithUserCode(0);
  }
}

}  // namespace quictun
