// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quictun/tcp_util.h"

#include <netdb.h>
#include <sys/socket.h>

#include <cstring>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/platform/api/quic_ip_address_family.h"
#include "quiche/quic/platform/api/quic_socket_address.h"

namespace quictun {

absl::StatusOr<quic::QuicSocketAddress> ResolveHostPort(
    absl::string_view host_port) {
  std::string host;
  std::string port;
  if (!host_port.empty() && host_port[0] == '[') {
    // IPv6 literal: "[host]:port". The host itself contains colons, so it
    // must be bracket-delimited to disambiguate from the port separator;
    // getaddrinfo() rejects the brackets themselves, so strip them here
    // rather than passing e.g. "[::]" through as the node argument.
    size_t close = host_port.find(']');
    if (close == absl::string_view::npos || close + 1 >= host_port.size() ||
        host_port[close + 1] != ':' || close + 2 == host_port.size()) {
      return absl::InvalidArgumentError(
          absl::StrCat("expected \"[host]:port\", got \"", host_port, "\""));
    }
    host = std::string(host_port.substr(1, close - 1));
    port = std::string(host_port.substr(close + 2));
  } else {
    size_t colon = host_port.find_last_of(':');
    if (colon == absl::string_view::npos || colon == host_port.size() - 1) {
      return absl::InvalidArgumentError(
          absl::StrCat("expected \"host:port\", got \"", host_port, "\""));
    }
    host = std::string(host_port.substr(0, colon));
    port = std::string(host_port.substr(colon + 1));
  }
  if (host.empty()) {
    host = "0.0.0.0";
  }

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo* result = nullptr;
  int err = getaddrinfo(host.c_str(), port.c_str(), &hints, &result);
  if (err != 0 || result == nullptr) {
    return absl::NotFoundError(absl::StrCat("failed to resolve \"", host_port,
                                            "\": ", gai_strerror(err)));
  }
  quic::QuicSocketAddress address(result->ai_addr, result->ai_addrlen);
  freeaddrinfo(result);
  return address;
}

absl::StatusOr<quic::SocketFd> CreateListeningSocket(
    const quic::QuicSocketAddress& address, int backlog) {
  quic::IpAddressFamily family = address.host().address_family();
  absl::StatusOr<quic::SocketFd> fd =
      quic::socket_api::CreateSocket(family, quic::socket_api::SocketProtocol::kTcp,
                                    /*blocking=*/false);
  if (!fd.ok()) return fd.status();

  // Without this, a restart can fail to rebind while the previous listening
  // socket's connections are still draining through TIME_WAIT.
  int reuse = 1;
  ::setsockopt(*fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

  absl::Status bind_status = quic::socket_api::Bind(*fd, address);
  if (!bind_status.ok()) {
    quic::socket_api::Close(*fd);
    return bind_status;
  }
  absl::Status listen_status = quic::socket_api::Listen(*fd, backlog);
  if (!listen_status.ok()) {
    quic::socket_api::Close(*fd);
    return listen_status;
  }
  return fd;
}

absl::StatusOr<quic::SocketFd> ConnectNonBlocking(
    const quic::QuicSocketAddress& address, bool* connecting) {
  quic::IpAddressFamily family = address.host().address_family();
  absl::StatusOr<quic::SocketFd> fd =
      quic::socket_api::CreateSocket(family, quic::socket_api::SocketProtocol::kTcp,
                                    /*blocking=*/false);
  if (!fd.ok()) return fd.status();

  absl::Status connect_status = quic::socket_api::Connect(*fd, address);
  if (connect_status.ok()) {
    *connecting = false;
    return fd;
  }
  if (absl::IsUnavailable(connect_status)) {
    *connecting = true;
    return fd;
  }
  quic::socket_api::Close(*fd);
  return connect_status;
}

}  // namespace quictun
