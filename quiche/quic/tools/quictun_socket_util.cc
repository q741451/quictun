// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_socket_util.h"

#include <cerrno>
#include <cstring>
#include <utility>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#include "absl/strings/str_cat.h"
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_udp_socket.h"
#include "quiche/quic/platform/api/quic_ip_address_family.h"
#include "quiche/quic/platform/api/quic_socket_address.h"

namespace quic {

namespace {

absl::Status SetSockOpt(SocketFd fd, int level, int option_name,
                        int value) {
#if defined(_WIN32)
  if (setsockopt(fd, level, option_name, reinterpret_cast<const char*>(&value),
                 sizeof(value)) != 0) {
    return absl::InternalError(
        absl::StrCat("setsockopt() failed: WSA error ", WSAGetLastError()));
  }
#else
  if (setsockopt(fd, level, option_name, &value, sizeof(value)) != 0) {
    return absl::ErrnoToStatus(errno, "setsockopt() failed");
  }
#endif
  return absl::OkStatus();
}

}  // namespace

absl::Status SetIpv6OnlyDisabled(SocketFd fd) {
  return SetSockOpt(fd, IPPROTO_IPV6, IPV6_V6ONLY, /*value=*/0);
}

absl::Status SetReuseAddrAndPort(SocketFd fd) {
#if defined(_WIN32)
  // Windows inverts both: SO_REUSEADDR is what lets another process take
  // over a bound port, and a listening socket can rebind a port in
  // TIME_WAIT without it. So it gets SO_EXCLUSIVEADDRUSE instead, as
  // Chromium sets on every server socket (net/socket/tcp_socket_win.cc,
  // SetExclusiveAddrUse()); a second quictun_server then fails to bind.
  return SetSockOpt(fd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, /*value=*/1);
#else
  absl::Status status = SetSockOpt(fd, SOL_SOCKET, SO_REUSEADDR, /*value=*/1);
  if (!status.ok()) {
    return status;
  }
#if defined(__linux__)
  return SetSockOpt(fd, SOL_SOCKET, SO_REUSEPORT, /*value=*/1);
#else
  // Elsewhere SO_REUSEPORT does not spread load across processes, so a
  // second quictun_server would bind the same port and silently share or
  // steal its traffic. Without it a second bind fails, loudly.
  return absl::OkStatus();
#endif  // defined(__linux__)
#endif  // defined(_WIN32)
}

absl::StatusOr<OwnedSocketFd> CreateQuicUdpSocket(
    const QuicSocketAddress& address_for_family, QuicByteCount buffer_bytes) {
  SocketFd fd = QuicUdpSocketApi().Create(
      address_for_family.host().AddressFamilyToInt(),
      /*receive_buffer_size=*/static_cast<int>(buffer_bytes),
      /*send_buffer_size=*/static_cast<int>(buffer_bytes));
  if (fd == kInvalidSocketFd) {
    return absl::InternalError("QuicUdpSocketApi::Create failed");
  }
#if defined(_WIN32)
  // Windows turns an ICMP port or network unreachable into a WSAECONNRESET or
  // WSAENETRESET on the next receive, unconnected sockets included -- where
  // Linux reports nothing at all. quictun never acts on those (6990cb05d:
  // ICMP is trivially spoofed, and transient unreachables heal), so turn the
  // reports off at the source, as Go's net package does for every UDP socket
  // (net/fd_windows.go; go.dev/issue/5834, go.dev/issue/68614).
  constexpr struct {
    DWORD code;
    const char* name;
  } kUnreachableReports[] = {
      {SIO_UDP_CONNRESET, "SIO_UDP_CONNRESET"},
      {SIO_UDP_NETRESET, "SIO_UDP_NETRESET"},
  };
  for (const auto& [code, name] : kUnreachableReports) {
    BOOL report = FALSE;
    DWORD bytes_returned = 0;
    if (WSAIoctl(fd, code, &report, sizeof(report), nullptr, 0,
                 &bytes_returned, nullptr, nullptr) != 0) {
      const int error = WSAGetLastError();
      QuicUdpSocketApi().Destroy(fd);
      return absl::InternalError(absl::StrCat("WSAIoctl(", name,
                                              ") failed: WSA error ", error));
    }
  }
#endif
  // Best-effort: kernel RX timestamping (SOF_TIMESTAMPING_RX_SOFTWARE) marks
  // each packet with the time it actually arrived, in softirq context --
  // more accurate than timestamping in userspace after recvmmsg() returns,
  // which under load (event loop busy servicing other connections/sockets)
  // can lag actual arrival by however long that delay was, inflating RTT
  // samples. Consumed in QuicPacketReader::ReadAndDispatchPackets(). Silently
  // no-ops if the kernel doesn't support it (see quic_udp_socket.cc); not
  // treated as fatal since RTT accuracy degrades gracefully without it.
  QuicUdpSocketApi().EnableReceiveTimestamp(fd);
  return OwnedSocketFd(fd);
}

absl::StatusOr<OwnedSocketFd> CreateListenUdpSocket(
    const QuicSocketAddress& address, QuicByteCount buffer_bytes) {
  absl::StatusOr<OwnedSocketFd> owned_fd =
      CreateQuicUdpSocket(address, buffer_bytes);
  if (!owned_fd.ok()) {
    return owned_fd.status();
  }

  if (address.host().address_family() == IpAddressFamily::IP_V6) {
    absl::Status status = SetIpv6OnlyDisabled(**owned_fd);
    if (!status.ok()) {
      return status;
    }
  }

  return std::move(*owned_fd);
}

}  // namespace quic
