// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Small helpers shared by quictun_client_connection.cc and
// quictun_server_connection.cc: picking a QuicPacketWriter (plain vs.
// SO_TXTIME-capable GSO batch writer) and applying the requested congestion
// control algorithm, so that logic isn't duplicated between the two sides.

#ifndef QUICHE_QUIC_TOOLS_QUICTUN_CONNECTION_FACTORY_H_
#define QUICHE_QUIC_TOOLS_QUICTUN_CONNECTION_FACTORY_H_

#include <memory>
#include <string>

#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_packet_writer.h"

namespace quic {

// Enables the SO_TXTIME restart flag process-wide. Must be called (once, at
// startup) before constructing any writer via MakeQuictunPacketWriter() with
// `so_txtime_enabled=true`, since QuicGsoBatchWriter only enables release
// time if the flag is already set at construction time.
void EnableQuictunSoTxTime();

// Returns a QuicDefaultPacketWriter, or -- if `so_txtime_enabled` -- a
// QuicGsoBatchWriter (Linux packet pacing offload). Falls back silently to
// the plain writer if the kernel doesn't support SO_TXTIME, same as
// QuicGsoBatchWriter always does when release time isn't available.
std::unique_ptr<QuicPacketWriter> MakeQuictunPacketWriter(
    SocketFd fd, bool so_txtime_enabled);

// Parses "cubic" | "bbr" | "bbr2" | "bbr3" into a CongestionControlType.
// Returns kCubicBytes (quictun's default) and logs a warning for any other
// value.
CongestionControlType ParseQuictunCongestionControl(
    const std::string& value);

// Applies `type` to `connection`'s own send direction. Bypasses QUIC's
// connection-option tag negotiation entirely (see quictun_connection_factory.cc
// for why) -- safe to call any number of times.
void SetQuictunCongestionControl(QuicConnection* connection,
                                 CongestionControlType type);

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_CONNECTION_FACTORY_H_
