// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUICTUN_QUICTUN_BACKEND_H_
#define QUICHE_QUICTUN_QUICTUN_BACKEND_H_

#include <string>

#include "quiche/quic/core/web_transport_interface.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/quic_server.h"
#include "quiche/quic/tools/quic_simple_server_backend.h"
#include "quiche/common/http/http_header_block.h"

namespace quictun {

// The quictun-server backend: every WebTransport session that presents the
// correct auth token (see quictun_auth.h) gets a ServerTunnelSessionVisitor
// that dials `target` for each of its incoming streams. Anything else (plain
// HTTP/3 requests, WebTransport sessions with a missing/wrong token) is
// rejected. This is quictun's server-side counterpart to kcptun server's
// `-key`/`-target` flags.
//
// Needs a pointer back to the owning QuicServer (for its event loop) rather
// than a QuicEventLoop directly, because (a) QuicServer only creates its
// event loop inside CreateUDPSocketAndListen(), and (b) QuicServer itself
// must be constructed with a pointer to this backend. Construct the backend
// first, pass it to QuicServer's constructor, then call SetServer() once the
// QuicServer object exists (and before CreateUDPSocketAndListen()).
class QuictunBackend : public quic::QuicSimpleServerBackend {
 public:
  QuictunBackend(quic::QuicSocketAddress target, std::string auth_token,
                bool quiet);

  void SetServer(quic::QuicServer* server) { server_ = server; }

  bool InitializeBackend(const std::string& /*backend_url*/) override {
    return true;
  }
  bool IsBackendInitialized() const override { return true; }
  void FetchResponseFromBackend(const quiche::HttpHeaderBlock& request_headers,
                                const std::string& request_body,
                                RequestHandler* request_handler) override;
  void CloseBackendResponseStream(RequestHandler* /*request_handler*/) override {
  }
  bool SupportsWebTransport() override { return true; }
  WebTransportResponse ProcessWebTransportRequest(
      const quiche::HttpHeaderBlock& request_headers,
      quic::WebTransportSession* session) override;

 private:
  quic::QuicServer* server_ = nullptr;
  quic::QuicSocketAddress target_;
  std::string auth_token_;
  bool quiet_;
};

}  // namespace quictun

#endif  // QUICHE_QUICTUN_QUICTUN_BACKEND_H_
