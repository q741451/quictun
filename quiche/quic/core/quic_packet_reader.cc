// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_packet_reader.h"

#include "absl/base/macros.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_process_packet_interface.h"
#include "quiche/quic/core/quic_udp_socket.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_server_stats.h"
#include "quiche/quic/platform/api/quic_socket_address.h"

namespace quic {

QuicPacketReader::QuicPacketReader()
    : read_buffers_(kNumPacketsPerReadMmsgCall),
      read_results_(kNumPacketsPerReadMmsgCall) {
  QUICHE_DCHECK_EQ(read_buffers_.size(), read_results_.size());
  for (size_t i = 0; i < read_results_.size(); ++i) {
    read_results_[i].packet_buffer.buffer = read_buffers_[i].packet_buffer;
    read_results_[i].packet_buffer.buffer_len =
        sizeof(read_buffers_[i].packet_buffer);

    read_results_[i].control_buffer.buffer = read_buffers_[i].control_buffer;
    read_results_[i].control_buffer.buffer_len =
        sizeof(read_buffers_[i].control_buffer);
  }
}

QuicPacketReader::~QuicPacketReader() = default;

bool QuicPacketReader::ReadAndDispatchPackets(
    int fd, int port, const QuicClock& clock, ProcessPacketInterface* processor,
    QuicPacketCount* /*packets_dropped*/) {
  // Reset all read_results for reuse.
  for (size_t i = 0; i < read_results_.size(); ++i) {
    read_results_[i].Reset(
        /*packet_buffer_length=*/sizeof(read_buffers_[i].packet_buffer));
  }

  // Use clock.Now() as the packet receipt time, the time between packet
  // arriving at the host and now is considered part of the network delay.
  // wall_now is clock.WallNow() taken at the same moment as `now`: if a
  // given packet has a kernel-provided RECV_TIMESTAMP (see
  // QuicUdpSocketApi::EnableReceiveTimestamp()), the two together let that
  // per-packet QuicWallTime be converted into an offset from `now` below,
  // since QuicTime and QuicWallTime aren't otherwise directly comparable.
  QuicTime now = QuicTime::Zero();
  QuicWallTime wall_now = QuicWallTime::Zero();
  if (!GetQuicReloadableFlag(quic_move_clock_now)) {
    now = clock.Now();
    wall_now = clock.WallNow();
  }

  QuicUdpPacketInfoBitMask info_bits(
      {QuicUdpPacketInfoBit::DROPPED_PACKETS,
       QuicUdpPacketInfoBit::PEER_ADDRESS, QuicUdpPacketInfoBit::V4_SELF_IP,
       QuicUdpPacketInfoBit::V6_SELF_IP, QuicUdpPacketInfoBit::RECV_TIMESTAMP,
       QuicUdpPacketInfoBit::TTL, QuicUdpPacketInfoBit::GOOGLE_PACKET_HEADER,
       QuicUdpPacketInfoBit::V6_FLOW_LABEL});
  QUIC_CODE_COUNT(quic_record_tos_byte);
  // Note ToS bit will also populate ECN codepoint.
  info_bits.Set(QuicUdpPacketInfoBit::TOS);
  size_t packets_read =
      socket_api_.ReadMultiplePackets(fd, info_bits, &read_results_);
  if (GetQuicReloadableFlag(quic_move_clock_now)) {
    QUIC_CODE_COUNT(quic_move_clock_now);
    now = clock.Now();
    wall_now = clock.WallNow();
  }
  for (size_t i = 0; i < packets_read; ++i) {
    auto& result = read_results_[i];
    if (!result.ok) {
      QUIC_CODE_COUNT(quic_packet_reader_read_failure);
      continue;
    }

    if (!result.packet_info.HasValue(QuicUdpPacketInfoBit::PEER_ADDRESS)) {
      QUIC_BUG(quic_bug_10329_1) << "Unable to get peer socket address.";
      continue;
    }

    QuicSocketAddress peer_address =
        result.packet_info.peer_address().Normalized();

    QuicIpAddress self_ip = GetSelfIpFromPacketInfo(
        result.packet_info, peer_address.host().IsIPv6());
    if (!self_ip.IsInitialized()) {
      QUIC_BUG(quic_bug_10329_2) << "Unable to get self IP address.";
      continue;
    }

    bool has_ttl = result.packet_info.HasValue(QuicUdpPacketInfoBit::TTL);
    int ttl = has_ttl ? result.packet_info.ttl() : 0;
    if (!has_ttl) {
      QUIC_CODE_COUNT(quic_packet_reader_no_ttl);
    }

    char* headers = nullptr;
    size_t headers_length = 0;
    if (result.packet_info.HasValue(
            QuicUdpPacketInfoBit::GOOGLE_PACKET_HEADER)) {
      headers = result.packet_info.google_packet_headers().buffer;
      headers_length = result.packet_info.google_packet_headers().buffer_len;
    } else {
      QUIC_CODE_COUNT(quic_packet_reader_no_google_packet_header);
    }
    uint32_t flow_label = 0;
    if (result.packet_info.HasValue(QuicUdpPacketInfoBit::V6_FLOW_LABEL)) {
      flow_label = result.packet_info.flow_label();
    }

    // Prefer the kernel's own per-packet receive timestamp over the single
    // `now` snapshot taken for the whole batch, when available -- under
    // load, a batch read can return many packets at once (see
    // kNumPacketsPerReadMmsgCall), and packets earlier in that batch may
    // actually have arrived measurably before `now`. QuicWallTime isn't
    // directly comparable to QuicTime (different, implementation-defined
    // epochs), so convert via the offset from `wall_now`, itself captured
    // at essentially the same instant as `now`.
    QuicTime packet_time = now;
    if (result.packet_info.HasValue(QuicUdpPacketInfoBit::RECV_TIMESTAMP)) {
      packet_time =
          now - wall_now.AbsoluteDifference(result.packet_info.receive_timestamp());
    }

    QuicReceivedPacket packet(
        result.packet_buffer.buffer, result.packet_buffer.buffer_len,
        packet_time, /*owns_buffer=*/false, ttl, has_ttl, headers,
        headers_length, /*owns_header_buffer=*/false,
        result.packet_info.ecn_codepoint(), result.packet_info.GetTos(),
        flow_label);
    QuicSocketAddress self_address(self_ip, port);
    processor->ProcessPacket(self_address, peer_address, packet);
  }

  // We may not have read all of the packets available on the socket.
  return packets_read == kNumPacketsPerReadMmsgCall;
}

// static
QuicIpAddress QuicPacketReader::GetSelfIpFromPacketInfo(
    const QuicUdpPacketInfo& packet_info, bool prefer_v6_ip) {
  if (prefer_v6_ip) {
    if (packet_info.HasValue(QuicUdpPacketInfoBit::V6_SELF_IP)) {
      return packet_info.self_v6_ip();
    }
    if (packet_info.HasValue(QuicUdpPacketInfoBit::V4_SELF_IP)) {
      return packet_info.self_v4_ip();
    }
  } else {
    if (packet_info.HasValue(QuicUdpPacketInfoBit::V4_SELF_IP)) {
      return packet_info.self_v4_ip();
    }
    if (packet_info.HasValue(QuicUdpPacketInfoBit::V6_SELF_IP)) {
      return packet_info.self_v6_ip();
    }
  }
  return QuicIpAddress();
}

}  // namespace quic
