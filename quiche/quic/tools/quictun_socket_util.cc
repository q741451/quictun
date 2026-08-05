// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_socket_util.h"

#include <cerrno>
#include <cstring>
#include <utility>

#include <netinet/in.h>
#include <sys/socket.h>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_udp_socket.h"
#include "quiche/quic/platform/api/quic_ip_address_family.h"
#include "quiche/quic/platform/api/quic_socket_address.h"

namespace quic {

namespace {

absl::Status SetSockOpt(SocketFd fd, int level, int option_name,
                        int value) {
  if (setsockopt(fd, level, option_name, &value, sizeof(value)) != 0) {
    return absl::ErrnoToStatus(errno, "setsockopt() failed");
  }
  return absl::OkStatus();
}

}  // namespace

absl::Status SetIpv6OnlyDisabled(SocketFd fd) {
  return SetSockOpt(fd, IPPROTO_IPV6, IPV6_V6ONLY, /*value=*/0);
}

absl::Status SetReuseAddrAndPort(SocketFd fd) {
  absl::Status status = SetSockOpt(fd, SOL_SOCKET, SO_REUSEADDR, /*value=*/1);
  if (!status.ok()) {
    return status;
  }
  return SetSockOpt(fd, SOL_SOCKET, SO_REUSEPORT, /*value=*/1);
}

absl::StatusOr<OwnedSocketFd> CreateQuicUdpSocket(
    const QuicSocketAddress& address_for_family) {
  SocketFd fd = QuicUdpSocketApi().Create(
      address_for_family.host().AddressFamilyToInt(),
      /*receive_buffer_size=*/kDefaultSocketReceiveBuffer,
      /*send_buffer_size=*/kDefaultSocketReceiveBuffer);
  if (fd == kInvalidSocketFd) {
    return absl::InternalError("QuicUdpSocketApi::Create failed");
  }
  return OwnedSocketFd(fd);
}

absl::StatusOr<OwnedSocketFd> CreateReusableUdpSocket(
    const QuicSocketAddress& address) {
  absl::StatusOr<OwnedSocketFd> owned_fd = CreateQuicUdpSocket(address);
  if (!owned_fd.ok()) {
    return owned_fd.status();
  }

  absl::Status status = SetReuseAddrAndPort(**owned_fd);
  if (!status.ok()) {
    return status;
  }

  if (address.host().address_family() == IpAddressFamily::IP_V6) {
    status = SetIpv6OnlyDisabled(**owned_fd);
    if (!status.ok()) {
      return status;
    }
  }

  return std::move(*owned_fd);
}

}  // namespace quic
