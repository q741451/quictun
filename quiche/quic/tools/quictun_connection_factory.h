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

#include <cstdint>
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

// Manual startup-state tuning -- see --startup_bandwidth_kbps/
// --startup_rtt_ms in quictun_flags.cc. Bootstraps `connection`'s
// congestion controller with an assumed starting bandwidth/RTT (see
// SendAlgorithmInterface::NetworkParams and, for BBR2 specifically,
// Bbr2Sender::AdjustNetworkParameters -- it only has an effect while
// still in STARTUP). No-op if `bandwidth_kbps <= 0`.
void SetQuictunStartupBandwidthHint(QuicConnection* connection,
                                    int32_t bandwidth_kbps, int32_t rtt_ms);

// Process-wide, not per-connection -- see --bbr_startup_loss_threshold_
// percent/--bbr_startup_full_loss_count in quictun_flags.cc.
// BbrSender::ShouldExitStartupDueToLoss() (bbr_sender.cc) makes BBRv1 give
// up on STARTUP -- i.e. stop probing for more bandwidth and settle for
// whatever it's already reached -- once a round sees enough loss events
// (default quic_bbr2_default_startup_full_loss_count = 8) AND the lost
// bytes exceed a fraction of bytes in flight (default
// quic_bbr2_default_loss_threshold = 0.02, i.e. 2%). On a path with
// genuine baseline loss above 2% (e.g. a long-haul/lossy link that can
// still sustain a real, higher bandwidth once ramped), this fires well
// before actually finding the true available bandwidth.
//
// These are process-wide QuicFlags (not per-connection QuicConfig), so
// this must be called exactly once at process startup, before any
// connection is created -- and it applies to every connection the process
// ever makes, not just one. `loss_threshold_percent` (e.g. 50 for 50%)
// and/or `full_loss_count` may each be 0 to leave that specific knob at
// QUICHE's own real default; a no-op call (both 0) is safe.
void ApplyQuictunBbrStartupLossOverrides(int32_t loss_threshold_percent,
                                         int32_t full_loss_count);

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_CONNECTION_FACTORY_H_
