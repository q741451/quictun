// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_connection_factory.h"

#include <ctime>
#include <memory>
#include <string>

#include "quiche/quic/core/batch_writer/quic_gso_batch_writer.h"
#include "quiche/quic/core/congestion_control/send_algorithm_interface.h"
#include "quiche/quic/core/io/quic_event_loop.h"
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

namespace {

// See MakeQuictunPacketWriter()'s comment for why this exists. Generalizes
// quic_client_default_network_helper.h's QuicLevelTriggeredPacketWriter
// (which only wraps QuicDefaultPacketWriter) into a decorator around any
// QuicPacketWriter, since quictun also uses QuicGsoBatchWriter -- and checks
// both WritePacket() *and* Flush(), since QuicGsoBatchWriter (batch mode)
// can report a newly-blocked write from either: WritePacket() itself when a
// full packet can't be buffered without flushing, or Flush() when an
// explicit/implicit flush of already-buffered packets hits the block.
class RearmOnBlockPacketWriter : public QuicPacketWriter {
 public:
  RearmOnBlockPacketWriter(std::unique_ptr<QuicPacketWriter> wrapped,
                           SocketFd fd, QuicEventLoop* event_loop)
      : wrapped_(std::move(wrapped)), fd_(fd), event_loop_(event_loop) {}

  WriteResult WritePacket(const char* buffer, size_t buf_len,
                          const QuicIpAddress& self_address,
                          const QuicSocketAddress& peer_address,
                          PerPacketOptions* options,
                          const QuicPacketWriterParams& params) override {
    WriteResult result = wrapped_->WritePacket(buffer, buf_len, self_address,
                                               peer_address, options, params);
    MaybeRearm(result);
    return result;
  }

  WriteResult Flush() override {
    WriteResult result = wrapped_->Flush();
    MaybeRearm(result);
    return result;
  }

  bool IsWriteBlocked() const override { return wrapped_->IsWriteBlocked(); }
  void SetWritable() override { wrapped_->SetWritable(); }
  std::optional<int> MessageTooBigErrorCode() const override {
    return wrapped_->MessageTooBigErrorCode();
  }
  QuicByteCount GetMaxPacketSize(
      const QuicSocketAddress& peer_address) const override {
    return wrapped_->GetMaxPacketSize(peer_address);
  }
  bool SupportsReleaseTime() const override {
    return wrapped_->SupportsReleaseTime();
  }
  bool IsBatchMode() const override { return wrapped_->IsBatchMode(); }
  bool SupportsEcn() const override { return wrapped_->SupportsEcn(); }
  QuicPacketBuffer GetNextWriteLocation(
      const QuicIpAddress& self_address,
      const QuicSocketAddress& peer_address) override {
    return wrapped_->GetNextWriteLocation(self_address, peer_address);
  }

 private:
  void MaybeRearm(const WriteResult& result) {
    if (!IsWriteBlockedStatus(result.status)) {
      return;
    }
    // Level-triggered only (SupportsEdgeTriggered() sockets don't consume
    // their subscription on firing, so have no need of this) -- see this
    // class's own comment, and QuictunClientConnection::OnSocketEvent()'s,
    // for why this specific rearm is otherwise never guaranteed to happen.
    if (!event_loop_->SupportsEdgeTriggered()) {
      bool success = event_loop_->RearmSocket(fd_, kSocketEventWritable);
      QUICHE_DCHECK(success);
    }
  }

  const std::unique_ptr<QuicPacketWriter> wrapped_;
  const SocketFd fd_;
  QuicEventLoop* const event_loop_;
};

}  // namespace

void EnableQuictunSoTxTime() {
  SetQuicRestartFlag(quic_support_release_time_for_gso, true);
}

std::unique_ptr<QuicPacketWriter> MakeQuictunPacketWriter(
    SocketFd fd, bool so_txtime_enabled, QuicEventLoop* event_loop) {
  std::unique_ptr<QuicPacketWriter> writer;
  if (so_txtime_enabled) {
    writer = std::make_unique<QuicGsoBatchWriter>(fd, CLOCK_MONOTONIC);
  } else {
    writer = std::make_unique<QuicDefaultPacketWriter>(fd);
  }
  return std::make_unique<RearmOnBlockPacketWriter>(std::move(writer), fd,
                                                     event_loop);
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
