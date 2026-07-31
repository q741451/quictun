// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUICTUN_TCP_UTIL_H_
#define QUICHE_QUICTUN_TCP_UTIL_H_

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/platform/api/quic_socket_address.h"

namespace quictun {

// Resolves "host:port" (host may be a numeric IP or a DNS name) into a
// QuicSocketAddress, via a blocking getaddrinfo() call. Only meant to be
// called at startup / on each new proxied connection, never on a hot path
// that must not block the event loop for long.
absl::StatusOr<quic::QuicSocketAddress> ResolveHostPort(
    absl::string_view host_port);

// Creates a bound, listening, non-blocking TCP socket for `address`.
absl::StatusOr<quic::SocketFd> CreateListeningSocket(
    const quic::QuicSocketAddress& address, int backlog = 128);

// Starts a non-blocking connect() to `address`. On return, `*connecting`
// indicates whether the connection is still in progress (true, the normal
// case for a non-blocking TCP connect) or was already established
// synchronously (false).
absl::StatusOr<quic::SocketFd> ConnectNonBlocking(
    const quic::QuicSocketAddress& address, bool* connecting);

}  // namespace quictun

#endif  // QUICHE_QUICTUN_TCP_UTIL_H_
