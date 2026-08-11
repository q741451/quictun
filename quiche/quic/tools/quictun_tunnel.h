// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Pumps bytes between one QuictunStream and one ConnectingClientSocket. Used
// symmetrically by both binaries: quictun_server plugs in a real
// EventLoopConnectingClientSocket dialing --target; quictun_client plugs in
// a QuictunAcceptedTcpSocket wrapping an already-accepted --local
// connection.
//
// Deliberately fully async in both directions (SendAsync/ReceiveAsync only,
// never the *Blocking calls) -- unlike quic/tools/connect_tunnel.cc, whose
// blocking calls are safe there because each HTTP/3 CONNECT tunnel only ever
// blocks its own single QUIC connection's processing. quictun instead runs
// many concurrent tunnels on one shared event-loop thread (one per QUIC
// connection, see quictun_client_driver.h / quictun_server_driver.h), so a
// blocking call here would stall every other tunnel in the process.

#ifndef QUICHE_QUIC_TOOLS_QUICTUN_TUNNEL_H_
#define QUICHE_QUIC_TOOLS_QUICTUN_TUNNEL_H_

#include <deque>
#include <functional>
#include <memory>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/connecting_client_socket.h"
#include "quiche/quic/core/quic_alarm.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/tools/quictun_session.h"
#include "quiche/common/quiche_mem_slice.h"

namespace quic {

class QUICHE_EXPORT QuictunTunnel : public ConnectingClientSocket::AsyncVisitor,
                                    public QuictunStreamDelegate {
 public:
  // `stream` must outlive this tunnel; the owning connection object
  // (QuictunClientConnection / QuictunServerConnection) is responsible for
  // that, and for destroying it and `socket` together. `on_closed` is
  // invoked (at most once) when the tunnel shuts down for any reason
  // (either side closing, or an I/O error) -- the owner should tear down the
  // whole connection (including the QUIC session/connection) in response.
  // `idle_timeout` mirrors shadowsocks-libev's server_t: a single timer
  // covering the whole tunnel, reset by real progress on either leg -- see
  // idle_alarm_'s comment.
  //
  // `socket`, unlike `stream`, may be omitted (nullptr) at construction and
  // supplied later via SetSocket() -- needed on the server side, where the
  // dial-out to --target is itself async (ConnectAsync(), never the
  // *Blocking calls -- see the class comment) and this tunnel is the
  // socket's AsyncVisitor, so the socket can't be constructed until this
  // tunnel already exists to pass as that visitor. QUIC->TCP data that
  // arrives before SetSocket() is called is queued exactly like data that
  // arrives while the socket is merely write-blocked (see pending_to_tcp_);
  // it's flushed once the socket is set.
  QuictunTunnel(QuictunStream* stream, ConnectingClientSocket* socket,
               QuicTime::Delta idle_timeout, std::function<void()> on_closed);

  // Supplies the socket when it wasn't available at construction (see the
  // constructor's comment). Must be called at most once, and only if
  // `socket` was null at construction. Does not itself begin pumping --
  // still must be followed by ConnectComplete() (if the socket is a fresh
  // dial-out still connecting) or Start() (if already connected).
  void SetSocket(ConnectingClientSocket* socket);

  // Whether SetSocket() (or a non-null `socket` at construction) has
  // actually happened yet. Exposed for the owner's on_closed callback (see
  // that constructor param's comment): if this tunnel closes -- for
  // whatever reason -- while this is still false, Close() never got a
  // chance to Disconnect() the target socket (it never had one to touch),
  // so the owner is the one that still needs to do that for whatever it
  // was about to hand over via SetSocket().
  bool HasSocket() const { return socket_ != nullptr; }

  // Begins pumping in both directions. `stream` must already be open and
  // `socket` (whether supplied at construction or via SetSocket()) must
  // already be connected. `seed_quic_to_tcp_data`, if non-empty, is queued
  // as already-received QUIC->TCP data before pumping starts -- used by the
  // server side, which reads and validates the client's key preamble itself
  // before constructing the tunnel, and may have already read past the
  // preamble into real payload bytes in the same Read() call (see
  // quictun_server_connection.cc).
  void Start(absl::string_view seed_quic_to_tcp_data = "");

  // QuictunStreamDelegate (QUIC -> TCP direction). A QuictunTunnel is always
  // scoped to exactly one stream (its own stream_), so the QuicStreamId
  // these are invoked with is always stream_->id() -- ignored.
  void OnStreamDataAvailable(QuicStreamId id) override;
  void OnStreamCanWriteMore(QuicStreamId id) override;
  void OnStreamClosed(QuicStreamId id) override;

  // ConnectingClientSocket::AsyncVisitor (TCP -> QUIC direction). On the
  // client side, where `socket` is already connected at construction and
  // the owner calls Start() itself, this is never invoked (matching
  // connect_tunnel.cc's own ConnectComplete(), which asserts the same for
  // its own, differently-shaped, reason). On the server side, this fires
  // once the async dial-out to --target (kicked off by the owner right
  // after SetSocket()) resolves: success calls Start() (with whatever seed
  // data the owner supplied when constructing this tunnel -- see
  // pending_seed_data_); failure closes the tunnel.
  void ConnectComplete(absl::Status status) override;
  void ReceiveComplete(absl::StatusOr<quiche::QuicheMemSlice> data) override;
  void SendComplete(absl::Status status) override;

  // Seed data to replay into Start() once ConnectComplete() fires -- set at
  // construction (see the constructor) instead of threaded through
  // ConnectComplete() itself, since the caller who has that data
  // (QuictunServerConnection, right after authenticating the stream) is not
  // the one who later observes ConnectComplete() (this tunnel is, as its
  // own AsyncVisitor). Empty and unused on the client side, which calls
  // Start() directly instead.
  void SetPendingSeedData(std::string seed_quic_to_tcp_data) {
    pending_seed_data_ = std::move(seed_quic_to_tcp_data);
  }

  // Called by FlushCloseAlarmDelegate / IdleAlarmDelegate (quictun_tunnel.cc);
  // not for other callers.
  void OnFlushCloseAlarm();
  void OnIdleAlarm();

 private:
  void BeginReadFromTcp();
  void MaybeFlushQuicToTcp();
  void Close(absl::string_view reason, bool reset_stream);

  // Rearms idle_alarm_ for idle_timeout_ from now -- called on any real
  // progress on either leg (see idle_alarm_'s comment).
  void ResetIdleAlarm();

  // Marks our own send direction done -- writing the stream's FIN if it
  // hasn't been written yet -- once the peer has finished sending (QUIC FIN
  // already seen) and every byte of that final delivery has actually been
  // forwarded to the TCP side. Mirrors quic/tools/connect_tunnel.cc's
  // OnClientStreamClose() (unconditional Disconnect()); see the comment on
  // quic_receive_done_. Actual teardown goes through MaybeFinalizeClose(),
  // same as the ReceiveComplete()-driven local-EOF path -- see its comment
  // on tcp_receive_done_ for why this can't just close immediately.
  void MaybeCloseAfterQuicFin();

  // Checks whether it's safe to finish tearing the tunnel down once
  // tcp_receive_done_ is set (by either MaybeCloseAfterQuicFin() or
  // ReceiveComplete() -- see its comment) -- closes if the stream has
  // actually finished sending (and, ideally, gotten acked; see
  // flush_close_alarm_'s comment), otherwise arms flush_close_alarm_ to
  // check again shortly.
  void MaybeFinalizeClose();

  // Reads as much currently-available data from `stream_` as fits in
  // `pending_to_tcp_` (up to kMaxQueuedChunks). Called both when new stream
  // data arrives (OnStreamDataAvailable) and whenever a queue slot frees up
  // (SendComplete) -- QuicStreamSequencer only invokes OnStreamDataAvailable
  // when new data arrives, so if a single burst of stream data exceeds the
  // queue's capacity, the leftover bytes must be pulled proactively once
  // room frees up. Otherwise they (and the QUIC-level flow-control credit
  // needed to unblock the sender, which is only released by reading) can get
  // stranded forever: the sender is blocked on flow control waiting for us
  // to read, and we're waiting for a callback that will never re-fire
  // because the sender never sends the new data that would trigger it.
  void FillQueueFromStream();

  QuictunStream* const stream_;
  // Not const: see SetSocket()'s comment. Never changes again once actually
  // set (to a real, non-null socket) -- callers just have to tolerate it
  // being null between construction and SetSocket() on the server path.
  ConnectingClientSocket* socket_;
  std::function<void()> on_closed_;
  // See SetPendingSeedData()'s comment.
  std::string pending_seed_data_;

  // Backpressure queue for QUIC->TCP bytes: QuictunStream::OnDataAvailable
  // is a synchronous callback (it must call Read() promptly to keep the QUIC
  // stream's flow control moving), but the TCP socket can only have one
  // SendAsync in flight at a time -- so reads that arrive while a send is
  // still in flight are queued here, up to kMaxQueuedChunks. Once the queue
  // is full, OnStreamDataAvailable stops calling Read() until it drains,
  // which lets unread bytes accumulate in the QUIC stream's own receive
  // buffer (bounded by its flow-control window) instead -- naturally
  // throttling the QUIC sender without needing any extra signaling.
  std::deque<std::string> pending_to_tcp_;
  bool tcp_send_in_flight_ = false;
  bool tcp_receive_in_flight_ = false;

  // Set once our own send direction is done and its FIN has been written to
  // the stream -- either because ReceiveComplete() saw TCP EOF from the
  // local socket, or because MaybeCloseAfterQuicFin() decided there's
  // nothing left to relay to it either way. Closing the tunnel right away
  // at that point (as an earlier version of this fix did, from both call
  // sites) is unsafe: QuicConnection::CloseConnection() unconditionally
  // discards any stream data that's been handed to WriteToStream() but not
  // yet actually sent on the wire (ClearQueuedPackets()) -- for a transfer
  // bigger than fits in the last few packets (e.g. quictun's own chaos
  // test's big_download check), that silently truncates the tail of a
  // completely legitimate response (or, symmetrically, an upload still
  // in flight when the peer hangs up first). See MaybeFinalizeClose()/
  // flush_close_alarm_ for the fix: wait for the stream to actually finish
  // sending (ideally get acked, so a lossy path's retransmissions have a
  // chance too) before finalizing.
  bool tcp_receive_done_ = false;

  // Bounds how long MaybeFinalizeClose() will wait for the stream to
  // actually flush (see tcp_receive_done_) before giving up and closing
  // anyway -- matches idle_timeout's role as an outer safety net: normally
  // the wait is at most a couple of RTTs, but if the peer has vanished and
  // acks will never come, don't hang the tunnel open indefinitely either.
  std::unique_ptr<QuicAlarm> flush_close_alarm_;
  QuicTime send_done_time_ = QuicTime::Zero();

  // Set once the QUIC stream has delivered its FIN (peer done sending --
  // see FillQueueFromStream()). ConnectingClientSocket exposes no
  // shutdown(SHUT_WR)-equivalent half-close, so quictun can't turn that into
  // a one-directional close of `socket_` the way a real half-close would;
  // instead, once every already-queued byte has actually been forwarded
  // (pending_to_tcp_ empty, nothing in flight -- see MaybeCloseAfterQuicFin()),
  // the whole tunnel is torn down, exactly like QUICHE's own
  // connect_tunnel.cc treats OnClientStreamClose(). Without this, a peer
  // that closes first while the TCP target is itself waiting for us to hang
  // up (e.g. any simple request/response service) leaves both ends open
  // forever: nothing ever half-closes, so OnStreamClosed() never fires, and
  // the connection accumulates as a leaked UDP+TCP socket pair -- this is
  // what caused permanently-100%-CPU-under-bursty-load, since short-lived
  // connections routinely have the local side finish first.
  bool quic_receive_done_ = false;

  bool closed_ = false;

  // Mirrors shadowsocks-libev's server_t: ONE shared idle timer for the
  // whole tunnel (not per-direction), reset by ResetIdleAlarm() on any real
  // data progress on EITHER leg (socket_ or stream_ -- see its call sites in
  // ReceiveComplete()/FillQueueFromStream()), closing the tunnel if it ever
  // fires. This is deliberately independent of QUIC's own idle_timeout: that
  // one resets on ANY connection-level activity, including the automatic
  // PING keepalive QuictunSessionBase::ShouldKeepConnectionAlive() always
  // requests, so it never actually fires in practice, and quictun needs a
  // real backstop for a tunnel where neither leg is doing anything
  // productive (e.g. socket_ connected to a target that itself expects the
  // peer to send the next request, which will never come). idle_timeout_ is
  // the operator-configured --idle_timeout_seconds value, reused rather
  // than adding a second timeout flag -- matching shadowsocks-libev's own
  // default (effectively very lax: MIN_TCP_IDLE_TIMEOUT is 24h) rather than
  // being some short, aggressive value.
  const QuicTime::Delta idle_timeout_;
  std::unique_ptr<QuicAlarm> idle_alarm_;

  static constexpr size_t kReadSize = 16 * 1024;
  static constexpr size_t kMaxQueuedChunks = 4;
};

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_TUNNEL_H_
