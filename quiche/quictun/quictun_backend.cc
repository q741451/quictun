// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quictun/quictun_backend.h"

#include <memory>
#include <string>
#include <utility>

#include "quiche/quic/tools/quic_backend_response.h"
#include "quiche/quictun/quictun_auth.h"
#include "quiche/quictun/session_visitors.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace quictun {

QuictunBackend::QuictunBackend(quic::QuicSocketAddress target,
                               std::string auth_token, bool quiet)
    : target_(target), auth_token_(std::move(auth_token)), quiet_(quiet) {}

void QuictunBackend::FetchResponseFromBackend(
    const quiche::HttpHeaderBlock& /*request_headers*/,
    const std::string& /*request_body*/, RequestHandler* request_handler) {
  static quic::QuicBackendResponse* response = []() {
    quiche::HttpHeaderBlock headers;
    headers[":status"] = "405";
    headers["content-type"] = "text/plain";
    auto response = std::make_unique<quic::QuicBackendResponse>();
    response->set_headers(std::move(headers));
    response->set_body("This endpoint only accepts quictun WebTransport requests");
    return response.release();
  }();
  request_handler->OnResponseBackendComplete(response);
}

QuictunBackend::WebTransportResponse QuictunBackend::ProcessWebTransportRequest(
    const quiche::HttpHeaderBlock& request_headers,
    quic::WebTransportSession* session) {
  WebTransportResponse response;

  auto auth = request_headers.find(kAuthHeader);
  if (auth == request_headers.end() ||
      !ConstantTimeEquals(auth->second, auth_token_)) {
    if (!quiet_) {
      QUICHE_LOG(INFO) << "rejected quictun connection: missing or invalid "
                       << kAuthHeader;
    }
    response.response_headers[":status"] = "403";
    return response;
  }

  response.response_headers[":status"] = "200";
  response.visitor = std::make_unique<ServerTunnelSessionVisitor>(
      session, server_->event_loop(), target_, quiet_);
  return response;
}

}  // namespace quictun
