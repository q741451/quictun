// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUICTUN_TUNNEL_PUMP_H_
#define QUICHE_QUICTUN_TUNNEL_PUMP_H_

#include <deque>
#include <memory>
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quictun/tunnel_id.h"
#include "quiche/web_transport/web_transport.h"

namespace quictun {

class TunnelPump;

// The actual per-stream webtransport::StreamVisitor. Streams own their
// visitor and garbage-collect it whenever the stream itself goes away (see
// the class comment on webtransport::StreamVisitor), which is incompatible
// with a TunnelPump that needs to outlive any single stream (autoexpire
// rotation re-homes a tunnel onto a fresh stream/connection without tearing
// down the TCP connection it represents -- see quictun_client_bin.cc).
// StreamAdapter bridges the two lifetimes: it is a thin, disposable object
// that forwards every callback to the TunnelPump it was created for, until
// Detach()'d.
class StreamAdapter : public webtransport::StreamVisitor {
 public:
  StreamAdapter(TunnelPump* parent, webtransport::Stream* stream)
      : parent_(parent), stream_(stream) {}
  ~StreamAdapter() override;

  StreamAdapter(const StreamAdapter&) = delete;
  StreamAdapter& operator=(const StreamAdapter&) = delete;

  void OnCanRead() override;
  void OnCanWrite() override;
  void OnResetStreamReceived(webtransport::StreamErrorCode error) override;
  void OnStopSendingReceived(webtransport::StreamErrorCode error) override;
  void OnWriteSideInDataRecvdState() override {}

  webtransport::Stream* stream() const { return stream_; }

  // Makes this adapter stop forwarding to `parent_`; called by TunnelPump
  // once it no longer wants callbacks from this particular stream (either
  // because the tunnel closed entirely, or because this stream was
  // superseded by a rotation). Safe to call more than once.
  void Detach() { parent_ = nullptr; }

 private:
  TunnelPump* parent_;
  webtransport::Stream* stream_;  // Not owned; see class comment.
};

// Pumps bytes bidirectionally between a plain TCP socket and a WebTransport
// bidirectional stream -- except the stream can be swapped out from under it
// via AttachStream(), so one logical tunnel (== one proxied TCP connection)
// can span several QUIC connections over its lifetime. This is what lets
// autoexpire move a tunnel to a fresh connection without disturbing the TCP
// connection riding on it.
//
// Ownership: a TunnelPump is owned by a TunnelRegistry, keyed by TunnelId,
// and is only ever destroyed by TunnelRegistry::SweepClosed(). CloseAll()
// deliberately never self-destructs or otherwise triggers its own deletion:
// an earlier version of this design did, and a TCP-side failure deep inside
// a stream callback could trigger CloseAll() while a caller further up the
// very same call stack still expected `this` to be alive afterwards --
// reentrant self-destruction, a real production segfault. Destruction is
// deferred to SweepClosed(), which must only ever be called from a point in
// the event loop that is provably not nested inside any TunnelPump/
// StreamAdapter callback (see quictun_server_bin.cc / quictun_client_bin.cc
// for the two call sites).
class TunnelPump : public quic::QuicSocketEventListener {
 public:
  // If `connecting` is true, `tcp_fd` is a socket for which a non-blocking
  // connect() is already in flight (used on the server side while dialing
  // the proxied target); the first writable event will check
  // socket_api::GetSocketError() before treating the connection as usable.
  TunnelPump(quic::QuicEventLoop* event_loop, quic::SocketFd tcp_fd,
             bool quiet, bool connecting, TunnelId id);
  ~TunnelPump() override;

  TunnelPump(const TunnelPump&) = delete;
  TunnelPump& operator=(const TunnelPump&) = delete;

  TunnelId id() const { return id_; }
  bool closed() const { return closed_; }

  // Binds this tunnel to `stream`, superseding whatever it was previously
  // attached to (if anything). `client_side` controls whether the
  // TunnelId wire header is written: only the client ever originates a new
  // stream for an existing tunnel; the server only ever continues one in
  // response to reading that header (see session_visitors.cc).
  // `initial_payload` replays any bytes already consumed off `stream`
  // before the caller could identify which tunnel it belongs to (the
  // TunnelId header itself, server-side).
  //
  // The stream this tunnel was previously attached to (if any) is SendFin()'d
  // -- not reset, and its underlying connection is not torn down here. This
  // lets QUIC keep delivering whatever was already buffered for it, and
  // lets the peer's read_queue_ advance past it as soon as that FIN
  // actually arrives, without either side waiting for the old connection
  // to go away. Nothing here blocks on that FIN ever arriving, though: if
  // the old connection is genuinely dead, the caller (quictun_client_bin.cc)
  // still tears it down after a bounded grace period, which unblocks the
  // peer's read_queue_ the slower way -- see CheckSessionReplacements().
  // Either way, this call itself never waits.
  void AttachStream(webtransport::Stream* stream, bool client_side,
                    absl::string_view initial_payload = "");

  // quic::QuicSocketEventListener implementation (events on the TCP fd).
  void OnSocketEvent(quic::QuicEventLoop* event_loop, quic::SocketFd fd,
                     quic::QuicSocketEventMask events) override;

 private:
  friend class StreamAdapter;

  struct PendingRead {
    webtransport::Stream* stream;
    // Bytes already read from `stream` before it was identified as
    // belonging to this tunnel; consumed before any further Read() calls.
    std::string seed;
  };

  // StreamAdapter callback forwarding; see StreamAdapter's class comment.
  void OnStreamCanRead(StreamAdapter* adapter);
  void OnStreamCanWrite(StreamAdapter* adapter);
  void OnStreamAborted(StreamAdapter* adapter);  // Reset or stop-sending.
  void OnStreamGone(StreamAdapter* adapter);      // Adapter destructor.
  // Un-tracks `adapter` (live_adapters_ + any read_queue_ entry for its
  // stream) without touching the stream itself; shared by OnStreamAborted
  // and OnStreamGone.
  void ForgetAdapter(StreamAdapter* adapter);

  void PumpSocketToStream();    // TCP socket -> current write stream.
  void PumpStreamToSocket();    // read_queue_ front -> TCP socket.
  bool FlushPendingToSocket();  // Returns true iff pending_to_socket_ drained.
  quic::QuicSocketEventMask DesiredMask() const;
  void RearmInterest();
  // Idempotent: detaches all streams, closes the TCP fd. `graceful` says
  // why: true for a clean completion (the local TCP side, or the peer,
  // finished with no error), false for a real failure. When true and
  // write_stream_ is still live, it gets SendFin()'d instead of
  // ResetWithUserCode()'d, so whatever was already Writev()'d into its
  // send buffer still gets delivered via QUIC's normal retransmission
  // instead of being silently discarded -- Reset() abandons that backlog
  // outright, which for a real transfer (not the toy payloads earlier
  // testing used) can be a substantial amount of data.
  void CloseAll(bool graceful = false);

  quic::QuicEventLoop* event_loop_;
  quic::SocketFd tcp_fd_;
  bool quiet_;
  bool connecting_;
  TunnelId id_;

  // Every StreamAdapter currently forwarding callbacks to this tunnel; not
  // owned (the underlying webtransport::Stream owns it, per the
  // StreamVisitor contract).
  std::vector<StreamAdapter*> live_adapters_;

  webtransport::Stream* write_stream_ = nullptr;  // Where new TCP-side reads
                                                   // get written; not owned.
  std::deque<PendingRead> read_queue_;

  // Data read from a stream but not yet fully written to the TCP socket.
  std::string pending_to_socket_;

  quic::QuicSocketEventMask registered_mask_ = 0;
  bool closed_ = false;
};

// Owns every TunnelPump that currently exists (server: every tunnel any
// client has ever opened and not yet finished; client: every tunnel
// autoexpire might rotate -- see quictun_client_bin.cc). Destruction only
// happens via SweepClosed(); see the class comment on TunnelPump for why
// that must only be called from a point in the event loop that is provably
// not nested inside any TunnelPump/StreamAdapter callback.
class TunnelRegistry {
 public:
  TunnelPump* Find(TunnelId id) {
    auto it = tunnels_.find(id);
    return it == tunnels_.end() ? nullptr : it->second.get();
  }

  TunnelPump* Register(TunnelId id, std::unique_ptr<TunnelPump> pump) {
    TunnelPump* ptr = pump.get();
    tunnels_[id] = std::move(pump);
    return ptr;
  }

  void SweepClosed() {
    // absl::flat_hash_map::erase(iterator) returns void (unlike
    // std::unordered_map), hence the post-increment-then-erase idiom.
    for (auto it = tunnels_.begin(); it != tunnels_.end();) {
      if (it->second->closed()) {
        tunnels_.erase(it++);
      } else {
        ++it;
      }
    }
  }

 private:
  absl::flat_hash_map<TunnelId, std::unique_ptr<TunnelPump>> tunnels_;
};

}  // namespace quictun

#endif  // QUICHE_QUICTUN_TUNNEL_PUMP_H_
