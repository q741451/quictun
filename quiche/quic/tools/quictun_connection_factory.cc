// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_connection_factory.h"

#include <cerrno>
#include <cstdlib>
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

// See SetQuictunStartupBandwidthHint()'s comment for why this exists.
// Matches QUICHE's own real quic_max_congestion_window default (2000
// packets, ~2.9 MB at the default 1460-byte MSS).
constexpr int32_t kStartupBandwidthHintMaxCongestionWindowPackets = 2000;

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

#ifdef QUICTUN_TEST_BUILD
// Test-only fault injector for writeblock_fault_test.py (see its own
// top-of-file comment): deterministically forces exactly one WritePacket()
// call to report WRITE_STATUS_BLOCKED, without touching the real socket, so
// tests can exercise RearmOnBlockPacketWriter's actual rearm mechanism on
// demand instead of hoping a genuine kernel sendmsg() EWOULDBLOCK happens to
// occur -- on loopback, real backpressure turns out to essentially never
// materialize (confirmed via strace: thousands of back-to-back sendmsg()
// calls against a 4KB SO_SNDBUF, zero EAGAIN -- loopback delivery is
// synchronous enough that the send buffer never visibly backs up), so a
// black-box test relying on it would be unreliable at best.
//
// Compiled in only under -DQUICTUN_TEST_BUILD (see MakeQuictunPacketWriter());
// entirely absent -- not just runtime-inert -- from every normal build,
// including CI's release artifacts (.github/workflows/build.yml never
// passes this macro). Runtime behavior is additionally still gated on
// QUICTUN_INJECT_WRITE_BLOCK_AFTER being set in the environment even when
// this macro is on, so a QUICTUN_TEST_BUILD binary run normally (env var
// unset) behaves identically to a normal build.
//
// Mirrors QuicDefaultPacketWriter's own IsWriteBlocked()/SetWritable()
// contract exactly (including its WritePacket()-entry DCHECK(!blocked)):
// QuicConnection reads writer_->IsWriteBlocked() as the source of truth
// after seeing IsWriteBlockedStatus(result.status) (see quic_connection.cc,
// e.g. right after SendPacket()'s WritePacket() call), not just the
// WriteResult itself, so an injector that only faked the return value
// without also flipping IsWriteBlocked() would trip QuicConnection's own
// consistency DCHECKs instead of exercising the rearm path cleanly.
class FaultInjectingPacketWriter : public QuicPacketWriter {
 public:
  FaultInjectingPacketWriter(std::unique_ptr<QuicPacketWriter> wrapped,
                             int trigger_after_n_writes)
      : wrapped_(std::move(wrapped)), remaining_(trigger_after_n_writes) {}

  WriteResult WritePacket(const char* buffer, size_t buf_len,
                          const QuicIpAddress& self_address,
                          const QuicSocketAddress& peer_address,
                          PerPacketOptions* options,
                          const QuicPacketWriterParams& params) override {
    QUICHE_DCHECK(!blocked_);
    if (MaybeInjectBlock()) {
      return WriteResult(WRITE_STATUS_BLOCKED, EWOULDBLOCK);
    }
    return wrapped_->WritePacket(buffer, buf_len, self_address, peer_address,
                                 options, params);
  }

  // Shares `remaining_` with WritePacket() rather than counting separately,
  // so the same QUICTUN_INJECT_WRITE_BLOCK_AFTER budget can land on
  // whichever call actually reaches the wire Nth -- necessary to reach
  // QuicGsoBatchWriter (--so_txtime): in batch mode, WritePacket() usually
  // just buffers into the pending GSO segment and reports OK immediately;
  // the real send (and thus the real place a block can happen) is Flush(),
  // called either explicitly or implicitly once the batch fills.
  WriteResult Flush() override {
    QUICHE_DCHECK(!blocked_);
    if (MaybeInjectBlock()) {
      return WriteResult(WRITE_STATUS_BLOCKED, EWOULDBLOCK);
    }
    return wrapped_->Flush();
  }

  bool IsWriteBlocked() const override {
    return blocked_ || wrapped_->IsWriteBlocked();
  }
  void SetWritable() override {
    blocked_ = false;
    wrapped_->SetWritable();
  }
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
  // Returns true (and flips blocked_) exactly once, on the call where
  // remaining_ reaches 0; false (decrementing remaining_ if still >= 0,
  // i.e. leaving it alone once already consumed) every other time.
  bool MaybeInjectBlock() {
    if (remaining_ == 0) {
      remaining_ = -1;  // Already fired -- stay armed-off, fire only once.
      blocked_ = true;
      return true;
    }
    if (remaining_ > 0) {
      --remaining_;
    }
    return false;
  }

  const std::unique_ptr<QuicPacketWriter> wrapped_;
  int remaining_;
  bool blocked_ = false;
};
#endif  // QUICTUN_TEST_BUILD

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
#ifdef QUICTUN_TEST_BUILD
  // Test-only, see FaultInjectingPacketWriter's own comment -- normal
  // (non-QUICTUN_TEST_BUILD) builds don't even contain this getenv() call.
  if (const char* trigger_after = std::getenv("QUICTUN_INJECT_WRITE_BLOCK_AFTER")) {
    writer = std::make_unique<FaultInjectingPacketWriter>(
        std::move(writer), std::atoi(trigger_after));
  }
#endif  // QUICTUN_TEST_BUILD
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
  // Bug fix: max_initial_congestion_window defaults to 0 in NetworkParams,
  // and 0 means "don't touch the ceiling" (see AdjustNetworkParameters()'s
  // own `if (params.max_initial_congestion_window > 0)` guard) -- so
  // without this, the bootstrapped window silently clamps to BbrSender's
  // own built-in default ceiling (kMaxInitialCongestionWindow, 200
  // packets, ~285 KB at the default MSS), regardless of how high
  // `bandwidth_kbps` is.
  params.max_initial_congestion_window =
      kStartupBandwidthHintMaxCongestionWindowPackets;
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
