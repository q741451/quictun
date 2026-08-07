// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_connection_factory.h"

#include <ctime>
#include <memory>
#include <string>

#include "quiche/quic/core/batch_writer/quic_gso_batch_writer.h"
#include "quiche/quic/core/congestion_control/send_algorithm_interface.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/quic_bandwidth.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_default_packet_writer.h"
#include "quiche/quic/core/quic_packet_writer.h"
#include "quiche/quic/core/quic_sent_packet_manager.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"

namespace quic {

void EnableQuictunSoTxTime() {
  SetQuicRestartFlag(quic_support_release_time_for_gso, true);
}

std::unique_ptr<QuicPacketWriter> MakeQuictunPacketWriter(
    SocketFd fd, bool so_txtime_enabled) {
  if (so_txtime_enabled) {
    return std::make_unique<QuicGsoBatchWriter>(fd, CLOCK_MONOTONIC);
  }
  return std::make_unique<QuicDefaultPacketWriter>(fd);
}

CongestionControlType ParseQuictunCongestionControl(const std::string& value) {
  if (value == "cubic") {
    return kCubicBytes;
  }
  if (value == "bbr") {
    return kBBR;
  }
  if (value == "bbr2") {
    return kBBRv2;
  }
  if (value == "bbr3") {
    return kBBRv3;
  }
  QUIC_LOG(WARNING) << "Unknown --congestion_control value \"" << value
                    << "\", using cubic";
  return kCubicBytes;
}

void SetQuictunCongestionControl(QuicConnection* connection,
                                 CongestionControlType type) {
  // QuicConfig's connection-option-tag negotiation (SetConnectionOptionsToSend
  // / SetClientConnectionOptions, consumed by
  // QuicSentPacketManager::SetFromConfig) is asymmetric by Perspective (a
  // server only reacts to options the *client* sent) and has no tag wired to
  // kBBRv3 in this snapshot -- neither lets an operator unilaterally pick
  // their own endpoint's algorithm via a purely local flag. quictun owns
  // both endpoints of its own protocol and doesn't need wire compatibility
  // with anything else, so it bypasses that machinery and sets the send
  // algorithm directly; each side's --congestion_control flag governs only
  // that side's own send direction, which is the technically correct
  // behavior in QUIC (each direction has its own controller).
  connection->sent_packet_manager().SetSendAlgorithm(type);
}

void SetQuictunStartupBandwidthHint(QuicConnection* connection,
                                    int32_t bandwidth_kbps, int32_t rtt_ms) {
  if (bandwidth_kbps <= 0) {
    return;
  }
  SendAlgorithmInterface::NetworkParams params(
      QuicBandwidth::FromKBitsPerSecond(bandwidth_kbps),
      QuicTime::Delta::FromMilliseconds(rtt_ms > 0 ? rtt_ms : kInitialRttMs),
      /*allow_cwnd_to_decrease=*/false);
  connection->AdjustNetworkParameters(params);
}

void ApplyQuictunBbrStartupLossOverrides(int32_t loss_threshold_percent,
                                         int32_t full_loss_count) {
  // See BbrSender::ShouldExitStartupDueToLoss() (bbr_sender.cc) -- despite
  // the "bbr2" in these flag names, they're read directly by BBRv1's own
  // STARTUP-loss-exit check, confirmed by grepping bbr_sender.cc itself
  // (not bbr2_sender.cc). Applied unconditionally, not gated behind a
  // sentinel: --bbr_startup_loss_threshold_percent/--bbr_startup_full_
  // loss_count default to QUICHE's own real defaults (2, 8) already (see
  // quictun_flags.h), so calling this with those defaults is a harmless
  // no-op that re-sets the flags to what they already were.
  SetQuicFlag(quic_bbr2_default_loss_threshold, loss_threshold_percent / 100.0);
  SetQuicFlag(quic_bbr2_default_startup_full_loss_count, full_loss_count);
}

}  // namespace quic
