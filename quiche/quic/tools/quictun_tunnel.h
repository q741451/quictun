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
#include "quiche/common/quiche_intrusive_list.h"
#include "quiche/common/quiche_mem_slice.h"

namespace quic {

class QuictunTunnel;

// Every live tunnel in the process, kept in one intrusive list ordered
// oldest-activity-first, so "has anything gone quiet long enough to close?"
// is an O(1) look at the head rather than a scan.
//
// Deliberately NOT a QuicAlarm per tunnel, which is what this replaced.
// QuicAlarmFactory is a connection-scoped scheduler for QUIC's own protocol
// events -- QuicConnection doesn't even give its twelve logical alarms one
// platform alarm each, it multiplexes them down to two (see
// QuicAlarmMultiplexer) -- and the queue backing QuicPollEventLoop holds a
// cancelled alarm's slot until that alarm's original deadline comes due,
// which is only affordable for the short deadlines QUICHE itself uses (its
// longest is kMaximumIdleTimeoutSecs, ten minutes). A per-tunnel alarm
// deadline of --tcp_idle_timeout_seconds turned every closed tunnel into a
// queue slot held for up to a day: measured ~100 bytes per TCP connection
// retained for the whole timeout, i.e. hundreds of MB at a few tens of new
// connections per second. A tunnel's silence is quictun's own concern, not
// the QUIC connection's, so it is tracked here with quictun's own
// bookkeeping and swept from quictun's own main loop instead.
class QUICHE_EXPORT QuictunIdleTracker {
 public:
  QuictunIdleTracker() = default;
  QuictunIdleTracker(const QuictunIdleTracker&) = delete;
  QuictunIdleTracker& operator=(const QuictunIdleTracker&) = delete;

  // Records that `tunnel` just moved real data, making it the most recently
  // active, and files it under `stalled` (see order_/stalled_order_).
  // Called only from QuictunTunnel::NoteActivity() and UpdateIdleClass().
  void Touch(QuictunTunnel* tunnel, bool stalled);

  // Moves an ALREADY-tracked `tunnel` between the two orderings. A no-op if
  // it isn't tracked: enrolling a tunnel is Start()'s job, via
  // NoteActivity(), and a tunnel that has not started yet has nothing for a
  // sweep to reason about.
  void Refile(QuictunTunnel* tunnel, bool stalled);

  // Drops `tunnel` from the ordering. Called only from
  // QuictunTunnel::Close(), which is the one and only unlink site -- see
  // idle_tracker_'s comment there. No-op if not currently linked.
  void Remove(QuictunTunnel* tunnel);

  // Closes every tunnel with no activity on either leg for long enough:
  // `timeout` for a tunnel holding nothing, `stalled_timeout` for one
  // holding buffered data (see stalled_order_). Cheap enough to call on
  // every event-loop iteration: returns after two comparisons unless
  // something has actually expired. Must only be called from outside any
  // tunnel's or connection's own call stack (the same requirement, and for
  // the same reason, as QuictunClientDriver::CollectGarbage()) -- closing a
  // tunnel reenters its owner.
  void CloseIdleTunnels(QuicTime now, QuicTime::Delta timeout,
                        QuicTime::Delta stalled_timeout);

 private:
  // Oldest activity at the front, so the front is the only expiry
  // candidate. Keeping it ordered is free: last_activity() only ever moves
  // forward to "now" and activity always moves the tunnel to the back, so
  // the list is sorted by construction -- nothing is ever compared, and
  // nothing is ever re-sorted.
  //
  // Non-owning, deliberately: a tunnel is owned by its connection's
  // stream_tcps_/stream_targets_ entry (a std::unique_ptr) and this is only
  // an index into those. QuicheIntrusiveList is what QUICHE itself uses for
  // exactly this shape -- see QuicBufferedPacketStore's
  // buffered_sessions_, which orders buffered connections for expiry the
  // same way -- and its own header spells out why it beats a
  // std::list<QuictunTunnel*> here: a std::list would heap-allocate a node
  // per element, an intrusive list allocates nothing at all.
  quiche::QuicheIntrusiveList<QuictunTunnel> order_;

  // The same ordering, for tunnels that are stalled rather than merely
  // quiet, swept against a much shorter timeout -- see
  // QuictunTuningOptions::tcp_stalled_timeout for why the two classes
  // cannot share one deadline. Two lists rather than one list and a
  // per-tunnel timeout, because the sweep's whole cost model rests on
  // "front not expired => nothing expired", which only holds while every
  // tunnel in a list is measured against the same value; one mixed list
  // would have to be walked in full on every event-loop iteration.
  // QuicheIntrusiveLink allows membership in only one list at a time, which
  // is exactly right here -- a tunnel is in one class or the other, and
  // QuictunTunnel::UpdateIdleClass() moves it across as that changes.
  quiche::QuicheIntrusiveList<QuictunTunnel> stalled_order_;
};

class QUICHE_EXPORT QuictunTunnel
    : public ConnectingClientSocket::AsyncVisitor,
      public QuictunStreamDelegate,
      // Membership in QuictunIdleTracker's ordering. Exempt from the style
      // guide's multiple-inheritance rule, per quiche_intrusive_list.h's own
      // note; QuicBufferedPacketStore::BufferedPacketListNode does the same.
      public quiche::QuicheIntrusiveLink<QuictunTunnel> {
 public:
  // `stream` must outlive this tunnel; the owning connection object
  // (QuictunClientConnection / QuictunServerConnection) is responsible for
  // that, and for destroying it and `socket` together. `on_closed` is
  // invoked (at most once) when the tunnel shuts down for any reason
  // (either side closing, or an I/O error) -- the owner should tear down the
  // whole connection (including the QUIC session/connection) in response.
  // `idle_tracker` (never null, must outlive this tunnel) is where this
  // tunnel registers its activity so the owner can find it if it ever goes
  // quiet -- see QuictunIdleTracker. The timeout value itself lives with
  // whoever sweeps, not here.
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
               QuictunIdleTracker* idle_tracker,
               std::function<void()> on_closed);

  ~QuictunTunnel() override;

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

  // When real data last moved on either leg. Read by QuictunIdleTracker
  // when sweeping; exposed rather than befriending it, since that is the
  // only thing it needs from this class.
  QuicTime last_activity() const { return last_activity_; }

  // Whether Close() has already run (for any reason) on this tunnel.
  // Exposed for an owner that needs to tear down several tunnels at once
  // and wants to safely call Close() on each -- Close() itself DCHECKs
  // !closed_, so an owner whose own cleanup can reenter (a tunnel's own
  // on_closed callback closing a sibling tunnel, say) needs a way to skip
  // ones already handled rather than hitting that DCHECK a second time.
  bool closed() const { return closed_; }

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
  void OnStreamGone(QuicStreamId id) override;

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

  // Called by FlushCloseAlarmDelegate (quictun_tunnel.cc); not for other
  // callers.
  void OnFlushCloseAlarm();

  // Tears this tunnel down: disconnects socket_ (if it has one) and, if
  // `reset_stream`, resets stream_ -- see the .cc definition's own
  // extensive comments for exactly what this does and why. Public so an
  // owner tearing down several tunnels at once (QuictunClientConnection::
  // Close() / QuictunServerConnection::Close()) can call this directly on
  // each -- see those methods' own comments for why going through this
  // real Close() (rather than a shortcut that only disconnects the
  // socket) matters: it's what sets closed_, which is what makes this
  // tunnel correctly no-op any of its own callbacks that are still
  // in-flight higher up the same call stack (e.g. a reentrant Close()
  // triggered while servicing a *different* stream's just-received
  // packet on the same connection). Must not be called a second time on
  // the same tunnel (QUICHE_DCHECK(!closed_) below) -- check closed()
  // first if that's possible (e.g. iterating a snapshot where an
  // earlier entry's own Close() might have reentrantly closed a later
  // one too).
  void Close(absl::string_view reason, bool reset_stream);

 private:
  void BeginReadFromTcp();
  void MaybeFlushQuicToTcp();

  // Records that real data moved on one of the legs, and moves this tunnel
  // to the tail of idle_tracker_ -- called on any real progress on either
  // leg (see last_activity_'s comment).
  void NoteActivity();

  // Whether this tunnel is holding buffered data it cannot hand on, in
  // either direction: pending_to_tcp_ full means FillQueueFromStream() has
  // stopped reading the stream, so unread bytes are piling up in the
  // sequencer and holding the connection's shared receive credit;
  // HasBufferedData() means ReceiveComplete() has stopped reading the TCP
  // socket, so bytes are piling up in the stream's send buffer. Either way
  // the cost is borne by the whole QUIC connection rather than by this
  // tunnel alone -- see stalled_'s comment.
  bool IsHoldingBuffer() const;

  // Re-files this tunnel under the right idle class if IsHoldingBuffer()
  // has changed since the last call. Must be called wherever that answer
  // can change -- which is NOT only from NoteActivity(): ReceiveComplete()
  // notes the activity and only then writes to the stream, so a tunnel
  // becomes stalled strictly after its last NoteActivity(), and by
  // definition may never have another.
  void UpdateIdleClass();

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
  // forever: nothing ever half-closes, so OnStreamGone() never fires, and
  // the connection accumulates as a leaked UDP+TCP socket pair -- this is
  // what caused permanently-100%-CPU-under-bursty-load, since short-lived
  // connections routinely have the local side finish first.
  bool quic_receive_done_ = false;

  bool closed_ = false;

  // Whether Start() has actually run yet. On the client, always true
  // essentially immediately (the owner calls Start() synchronously right
  // after construction -- `socket` is already connected there). On the
  // server, this tunnel already becomes stream_'s active delegate before
  // the (async, can take real time) --target dial-out is even initiated
  // -- see the class comment -- and false here (not HasSocket(), which
  // this class used to rely on for this, see OnStreamDataAvailable()'s
  // comment for why that's wrong) is what OnStreamDataAvailable() checks
  // to know it's not safe yet to call BeginReadFromTcp()/
  // MaybeFlushQuicToTcp() -- both of which assume socket_ is not just
  // non-null but actually connected.
  bool started_ = false;

  // ONE shared idle marker for the whole tunnel -- not per-direction, and
  // not per-connection -- updated by NoteActivity() on any real data
  // progress on EITHER leg (socket_ or stream_ -- see its call sites in
  // ReceiveComplete()/FillQueueFromStream()). Whoever sweeps idle_tracker_
  // closes the tunnel once this stops moving for long enough. It exists as
  // a backstop for a tunnel where neither leg is doing anything productive
  // -- e.g. socket_ connected to a target that itself expects the peer to
  // send the next request, which will never come.
  //
  // The timeout it is compared against (--tcp_idle_timeout_seconds) is
  // deliberately a separate knob from QUIC's own idle timeout
  // (--idle_timeout_seconds), because the two answer different questions
  // about different objects and their sensible values differ by orders of
  // magnitude. QUIC's resets on ANY packet received on the connection,
  // keepalive PINGs included, so while the peer is alive it never fires;
  // once the peer really is gone it is what reclaims the whole connection,
  // and every tunnel on it, within a minute. This one moves only on actual
  // payload, so it is the only thing that can ever notice a tunnel that is
  // merely quiet -- and since a vanished peer is already handled above, it
  // is free to be very lax, hence the 24h default. Sharing one flag for
  // both, as this used to, forced one of the two to be wrong: at 60s it cut
  // tunnels that were alive and simply idle, and at 24h it left vanished
  // peers' connections -- and every target-side fd hanging off them -- held
  // for a day.
  QuicTime last_activity_ = QuicTime::Zero();

  // Which of idle_tracker_'s two orderings this tunnel is currently filed
  // under (IsHoldingBuffer() as of the last UpdateIdleClass()), cached so
  // that call is a bool compare on paths that run after every chunk. Why
  // the two classes get different deadlines: see
  // QuictunTuningOptions::tcp_stalled_timeout.
  bool stalled_ = false;

  // Whether socket_ has already been disconnected, so Close() must not do it
  // again. Mirrors StreamTcp::tcp_socket_disconnected /
  // StreamTarget::target_socket_disconnected, which the owners use for the
  // same "don't disconnect twice" question one level up.
  //
  // Set by Close() itself when it does the disconnecting, and -- the case
  // that actually needs it -- by ConnectComplete() on a failed dial-out,
  // where the socket has already closed itself before calling back. Nothing
  // else self-closes: ReceiveComplete()/SendComplete() errors arrive with
  // the socket still open (FinishOrRearmAsyncReceive()/
  // FinishOrRearmAsyncSend() never Close()), so those still disconnect
  // normally.
  bool socket_disconnected_ = false;

  // Where this tunnel registers its activity. Linked by the first
  // NoteActivity() (from Start()), unlinked by Close() -- which is the ONLY
  // unlink site, not a best-effort one: between Close() and this object's
  // actual destruction the owner keeps it alive in its closed_stream_*
  // vector for a garbage-collection hop (see the owner's on_closed
  // callback), and a sweep reaching an already-closed tunnel in that window
  // would call Close() on it a second time. ~QuictunTunnel() therefore
  // asserts rather than tidying up: still being linked there means Close()
  // never ran, which already means a leaked fd and an owner that was never
  // told, not merely a stale list entry.
  QuictunIdleTracker* const idle_tracker_;

  static constexpr size_t kReadSize = 16 * 1024;
  static constexpr size_t kMaxQueuedChunks = 4;
};

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_TUNNEL_H_
