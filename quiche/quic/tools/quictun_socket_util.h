// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Low-level Linux socket helpers not exposed by quiche/quic/core/io/socket.h:
// IPv6 dual-stack, and the SO_REUSEADDR/SO_REUSEPORT + connect() combination
// quictun's server uses to migrate a new peer off the shared rendezvous
// socket onto its own dedicated, per-connection UDP socket (see
// quictun_server_driver.h for how this is used).

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

// Sets SO_REUSEADDR and SO_REUSEPORT on `fd`, allowing a later socket to bind
// to the same local address:port as an already-bound socket (used so a new
// per-connection socket can share the rendezvous socket's listen address;
// once it's also connect()ed to a specific peer, the kernel routes that
// peer's packets to the more-specific socket instead).
absl::Status SetReuseAddrAndPort(SocketFd fd);

// Creates a non-blocking UDP socket for `address_for_family`'s address
// family, with SO_RCVBUF/SO_SNDBUF both set to `buffer_bytes` (see
// --udp_socket_buffer_kb in quictun_flags.cc). Deliberately goes through
// QuicUdpSocketApi::Create() rather than the lower-level
// socket_api::CreateSocket(): only the former also enables the self-IP
// (IP_PKTINFO/IPV6_RECVPKTINFO) and ECN/TOS receive options that
// QuicPacketReader::ReadAndDispatchPackets() requires -- without them it
// QUIC_BUGs (fatally) on the first received packet with "Unable to get self
// IP address". Does not bind, connect, or set any other socket options.
absl::StatusOr<OwnedSocketFd> CreateQuicUdpSocket(
    const QuicSocketAddress& address_for_family, QuicByteCount buffer_bytes);

// Creates a non-blocking UDP socket for `address`'s family (see
// CreateQuicUdpSocket() above), with SO_REUSEADDR/SO_REUSEPORT set and, for
// IPv6, IPV6_V6ONLY disabled so the socket is dual-stack. Does not bind or
// connect it.
absl::StatusOr<OwnedSocketFd> CreateReusableUdpSocket(
    const QuicSocketAddress& address, QuicByteCount buffer_bytes);

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_SOCKET_UTIL_H_
