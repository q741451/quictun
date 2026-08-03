// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/congestion_control/hybrid_slow_start.h"

#include <algorithm>

#include "quiche/quic/platform/api/quic_logging.h"

namespace quic {

// quictun: the RTT-increase-detection constants that used to live here
// (kHybridStartLowWindow etc.) were dropped along with the logic that read
// them -- see the comment on ShouldExitSlowStart() below.

HybridSlowStart::HybridSlowStart()
    : started_(false),
      hystart_found_(NOT_FOUND),
      rtt_sample_count_(0),
      current_min_rtt_(QuicTime::Delta::Zero()) {}

void HybridSlowStart::OnPacketAcked(QuicPacketNumber acked_packet_number) {
  // OnPacketAcked gets invoked after ShouldExitSlowStart, so it's best to end
  // the round when the final packet of the burst is received and start it on
  // the next incoming ack.
  if (IsEndOfRound(acked_packet_number)) {
    started_ = false;
  }
}

void HybridSlowStart::OnPacketSent(QuicPacketNumber packet_number) {
  last_sent_packet_number_ = packet_number;
}

void HybridSlowStart::Restart() {
  started_ = false;
  hystart_found_ = NOT_FOUND;
}

void HybridSlowStart::StartReceiveRound(QuicPacketNumber last_sent) {
  QUIC_DVLOG(1) << "Reset hybrid slow start @" << last_sent;
  end_packet_number_ = last_sent;
  current_min_rtt_ = QuicTime::Delta::Zero();
  rtt_sample_count_ = 0;
  started_ = true;
}

bool HybridSlowStart::IsEndOfRound(QuicPacketNumber ack) const {
  return !end_packet_number_.IsInitialized() || end_packet_number_ <= ack;
}

bool HybridSlowStart::ShouldExitSlowStart(QuicTime::Delta /*latest_rtt*/,
                                          QuicTime::Delta /*min_rtt*/,
                                          QuicPacketCount /*congestion_window*/) {
  // quictun: HyStart's RTT-increase heuristic (the logic this used to run,
  // removed below) exits slow start -- switching from exponential to much
  // slower congestion-avoidance growth -- on any RTT bump of >=1/8 min_rtt.
  // On a path with a policer/shaper queue adding jitter well before it
  // actually drops anything, this fires long before real capacity is
  // reached, capping throughput far below what a scheme that only reacts
  // to actual loss (like KCP) gets. Slow start still ends the normal way,
  // via a real loss event in OnPacketLost() (which sets
  // slowstart_threshold_ = congestion_window_ there) -- this only removes
  // the *early*, RTT-based exit.
  return false;
}

}  // namespace quic
