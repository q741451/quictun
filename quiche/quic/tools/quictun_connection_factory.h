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
#include <optional>
#include <string>

#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_packet_writer.h"
#include "quiche/quic/platform/api/quic_socket_address.h"

namespace quic {

// Enables the SO_TXTIME restart flag process-wide. Must be called (once, at
// startup) before constructing any writer via MakeQuictunPacketWriter() with
// `so_txtime_enabled=true`, since QuicGsoBatchWriter only enables release
// time if the flag is already set at construction time.
void EnableQuictunSoTxTime();

// Returns a QuicDefaultPacketWriter, or -- if `so_txtime_enabled` -- a
// QuicGsoBatchWriter (Linux packet pacing offload) -- either way wrapped so
// that, the moment a write actually blocks, `event_loop` is told to resume
// watching `fd` for writability. Falls back silently to the plain writer if
// the kernel doesn't support SO_TXTIME, same as QuicGsoBatchWriter always
// does when release time isn't available.
//
// This rearming is necessary, not an optional nicety: quictun only ever asks
// its (poll()-based, always level-triggered -- see
// QuicEventLoop::SupportsEdgeTriggered()) event loop to keep watching a
// socket for writability while a write is actually known to be blocked, to
// avoid pinning a CPU core spinning through RunEventLoopOnce() on a socket
// that's (as UDP sockets almost always are) actually writable -- see
// QuictunClientConnection::OnSocketEvent()'s own comment on this. But the
// watch is armed by RearmSocket(), a one-shot subscription that POLLOUT
// consumes (see QuicPollEventLoop::ProcessIoEvents()) -- so if a write
// blocks for the first time right after the connection's initial
// registration already consumed that one-shot subscription (the ordinary
// case: sockets start out actually writable, so the very first poll() cycle
// fires kSocketEventWritable, finds nothing blocked yet, and -- correctly,
// by that same CPU-pinning-avoidance logic -- doesn't re-arm), nothing ever
// re-subscribes, and the socket is never told again that it's writable, even
// once it genuinely is -- the connection is stuck sending nothing, forever,
// with no error. Wrapping the writer here catches every blocked write at the
// one real choke point everything must pass through to actually reach the
// wire, so no call path can bypass it -- mirrors
// quic_client_default_network_helper.h's QuicLevelTriggeredPacketWriter
// (same fix, for QuicDefaultPacketWriter specifically; this generalizes it
// to also cover QuicGsoBatchWriter, which quictun uses too).
//
// Built with -DQUICTUN_TEST_BUILD (see writeblock_fault_test.py; not set by
// any normal build, including CI's release artifacts), the returned writer
// also fires a one-shot synthetic write-block -- see FaultInjectingPacketWriter
// in the .cc -- when QUICTUN_INJECT_WRITE_BLOCK_AFTER is set in the
// environment. Without that macro, none of this code exists in the binary
// at all, not just at runtime.
std::unique_ptr<QuicPacketWriter> MakeQuictunPacketWriter(
    SocketFd fd, bool so_txtime_enabled, QuicEventLoop* event_loop);

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
//
// Also sets NetworkParams::max_initial_congestion_window (see the .cc) --
// without it, the bootstrapped window silently clamps to BbrSender's own
// built-in 200-packet (~285 KB) default ceiling, regardless of how high
// `bandwidth_kbps` is: a real gap found while tracing through
// bbr_sender.cc's AdjustNetworkParameters(), since
// max_initial_congestion_window defaults to 0 in NetworkParams and 0
// means "don't touch the ceiling".
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
// ever makes, not just one. `loss_threshold_percent` is a percent (e.g.
// 50 for 50%), not a fraction. Both parameters default (in
// QuictunTuningOptions) to QUICHE's own real defaults (2, 8), so calling
// this with those defaults is a harmless no-op.
void ApplyQuictunBbrStartupLossOverrides(int32_t loss_threshold_percent,
                                         int32_t full_loss_count);

// --transparent (Linux only, quictun_client_driver.cc's AcceptLoop()): the
// original destination a freshly-accepted TCP connection was heading to
// before an external iptables/nftables REDIRECT rule sent it to --local
// instead (SO_ORIGINAL_DST) -- quictun itself never touches netfilter
// config, this only reads what a rule the operator set up separately
// already did. Tries the IPv6 variant (IP6T_SO_ORIGINAL_DST) first, then
// IPv4 (SO_ORIGINAL_DST) -- mirrors shadowsocks-libev's redir.c exactly,
// including its own reasoning for trying both rather than picking one
// upfront: there's no cheap way to know in advance which family a given
// fd's REDIRECT rule matched as. Returns nullopt (after logging why, at
// WARNING) if both fail -- most commonly because `fd` was connected to
// --local directly, never actually redirected by any rule at all.
std::optional<QuicSocketAddress> CaptureQuictunOriginalDestination(
    SocketFd fd);

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_CONNECTION_FACTORY_H_
