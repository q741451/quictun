// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Low-level Linux socket helpers not exposed by quiche/quic/core/io/socket.h.

#ifndef QUICHE_QUIC_TOOLS_QUICTUN_SOCKET_UTIL_H_
#define QUICHE_QUIC_TOOLS_QUICTUN_SOCKET_UTIL_H_

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_socket_address.h"

namespace quic {

// Disables IPV6_V6ONLY on `fd`, so a socket bound to an IPv6 wildcard/address
// also accepts IPv4 (mapped) traffic. Must be called before Bind(). `fd`
// must be an IPv6 socket (UDP or TCP); it is a no-op-equivalent error to call
// this on an IPv4 socket, so callers should only call it when the address
// being bound is IPv6.
absl::Status SetIpv6OnlyDisabled(SocketFd fd);

// Sets SO_REUSEADDR and SO_REUSEPORT on `fd`. Used on the client's --local
// TCP listener so a restart can rebind while its previous connections are
// still in TIME_WAIT.
absl::Status SetReuseAddrAndPort(SocketFd fd);

// Creates a non-blocking UDP socket for `address_for_family`'s address
// family, with SO_RCVBUF/SO_SNDBUF both set to `buffer_bytes` (see
// --udp_socket_buffer_kb in quictun_flags.cc) and kernel RX timestamping
// enabled (best-effort; see the .cc file). Deliberately goes through
// QuicUdpSocketApi::Create() rather than the lower-level
// socket_api::CreateSocket(): only the former also enables the self-IP
// (IP_PKTINFO/IPV6_RECVPKTINFO) and ECN/TOS receive options that
// QuicPacketReader::ReadAndDispatchPackets() requires -- without them it
// QUIC_BUGs (fatally) on the first received packet with "Unable to get self
// IP address". Does not bind, connect, or set any other socket options.
absl::StatusOr<OwnedSocketFd> CreateQuicUdpSocket(
    const QuicSocketAddress& address_for_family, QuicByteCount buffer_bytes);

// Creates a non-blocking UDP socket for `address`'s family (see
// CreateQuicUdpSocket() above) with, for IPv6, IPV6_V6ONLY disabled so an
// IPv6 wildcard also accepts IPv4. Does not bind it.
absl::StatusOr<OwnedSocketFd> CreateListenUdpSocket(
    const QuicSocketAddress& address, QuicByteCount buffer_bytes);

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_SOCKET_UTIL_H_
