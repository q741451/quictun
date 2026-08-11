// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A non-HTTP QUIC session/stream pair for quictun: each bidirectional QUIC
// stream carries one TCP connection's raw byte stream, with no HTTP/3 or
// WebTransport framing on top. This deliberately does not build on
// QuicGenericSessionBase (quic_generic_session.h): that class exists to
// expose a full WebTransport session (datagrams, stream priorities), none
// of which quictun needs.
//
// A session may carry more than one such stream at once -- see
// --quic_conn in quictun_flags.h: by default (--quic_conn=0) each
// QuictunClientConnection/QuictunServerConnection ever creates exactly one
// stream, unchanged from quictun's original one-stream-per-connection
// design, but when connection pooling is enabled a single session can be
// assigned many concurrent TCP tunnels, each as its own stream.

#ifndef QUICHE_QUIC_TOOLS_QUICTUN_SESSION_H_
#define QUICHE_QUIC_TOOLS_QUICTUN_SESSION_H_

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/crypto/quic_crypto_client_config.h"
#include "quiche/quic/core/crypto/quic_crypto_server_config.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_crypto_client_stream.h"
#include "quiche/quic/core/quic_crypto_server_stream_base.h"
#include "quiche/quic/core/quic_crypto_stream.h"
#include "quiche/quic/core/quic_server_id.h"
#include "quiche/quic/core/quic_session.h"
#include "quiche/quic/core/quic_stream.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_export.h"

namespace quic {

// The single QUIC version quictun speaks. Fixed, so there is no version
// negotiation code path to worry about.
QUICHE_EXPORT ParsedQuicVersionVector GetQuictunVersions();

// Receives events for one QuictunStream. Implemented by QuictunTunnel (see
// quictun_tunnel.h) -- which is always scoped to exactly one stream/tunnel,
// so it ignores `id` -- and, on the server, by QuictunServerConnection
// itself during a stream's pre-tunnel authentication phase, when one
// connection object is fielding this callback for however many of its
// streams haven't finished the --key preamble check yet and does need `id`
// to know which one. QuictunSessionBase itself implements this interface
// too and forwards each call to whichever delegate has been attached to
// that particular stream id, so events for a stream with no delegate
// attached yet are simply dropped.
class QUICHE_EXPORT QuictunStreamDelegate {
 public:
  virtual ~QuictunStreamDelegate() = default;

  // New bytes are readable on stream `id` (or its peer's FIN is readable).
  // The delegate should call QuictunStream::Read() to consume them.
  virtual void OnStreamDataAvailable(QuicStreamId id) = 0;

  // Stream `id` can accept more written data after being write-blocked.
  virtual void OnStreamCanWriteMore(QuicStreamId id) = 0;

  // Stream `id` has closed (FIN both ways, reset, or the connection
  // closed). The delegate must not touch that stream afterward.
  virtual void OnStreamClosed(QuicStreamId id) = 0;
};

// A QUIC stream carrying exactly one TCP connection's raw byte stream --
// direct WriteOrBufferData()/sequencer() use, no framing of any kind.
class QUICHE_EXPORT QuictunStream : public QuicStream {
 public:
  QuictunStream(QuicStreamId id, QuicSession* session,
                QuictunStreamDelegate* delegate);

  // QuicStream:
  void OnDataAvailable() override;
  void OnCanWriteNewData() override;
  void OnClose() override;

  // Reads up to buffer.size() bytes into buffer, returning the number of
  // bytes actually read. Sets *fin if the peer's FIN has now been fully
  // consumed (i.e. no more data will ever arrive on this stream).
  size_t Read(absl::Span<char> buffer, bool* fin);

  // Forwards TCP->QUIC bytes onto the stream. `fin` should be true exactly
  // once, when the TCP side has been fully read (half-close).
  void WriteToStream(absl::string_view data, bool fin);

  // Whether WriteToStream can currently accept more data without piling up
  // an unbounded amount of buffered (unsent) data.
  bool CanBufferMoreWrites() const;

  // QuicStream::session() is protected; exposed here so QuictunTunnel (not
  // a QuicStream subclass) can reach the connection's alarm factory/clock
  // for MaybeCloseAfterLocalEof()'s flush_close_alarm_.
  QuicConnection* connection();

 private:
  QuictunStreamDelegate* const delegate_;
};

// Shared logic for quictun's client and server sessions: custom ALPN (never
// "h3"), and forwarding of each stream's events to whichever
// QuictunStreamDelegate has been attached to that stream. Tracks every
// stream this session has ever created (see streams()); does not itself
// limit how many -- that policy (default: unlimited, but see --quic_conn)
// lives in QuictunClientConnection/QuictunServerConnection, closer to
// where the actual TCP-tunnel-per-stream bookkeeping already is.
class QUICHE_EXPORT QuictunSessionBase : public QuicSession,
                                          public QuictunStreamDelegate {
 public:
  QuictunSessionBase(QuicConnection* connection, Visitor* owner,
                      const QuicConfig& config, std::string alpn);

  // QuicSession:
  std::vector<std::string> GetAlpnsToOffer() const override;
  std::vector<absl::string_view>::const_iterator SelectAlpn(
      const std::vector<absl::string_view>& alpns) const override;
  void OnAlpnSelected(absl::string_view alpn) override;
  bool ShouldKeepConnectionAlive() const override { return true; }
  QuicStream* CreateIncomingStream(QuicStreamId id) override;

  // Opens a new outgoing stream for one more TCP tunnel on this session.
  // Safe to call immediately after CryptoConnect(), even before the
  // handshake is confirmed: if a 0-RTT session is available, QuicStream
  // buffers/sends the data at whatever encryption level is ready, same as
  // any other 0-RTT QUIC client (e.g. QuicSpdyClientBase). Returns nullptr
  // if the session can't open a new outgoing stream right now (no 0-RTT
  // session yet and the handshake hasn't supplied a max_streams value, or
  // the peer's advertised max_streams is already exhausted) -- the caller
  // is expected to retry, see QuictunClientConnection.
  QuictunStream* OpenOutgoingStream();

  // All streams this session currently has open, in no particular order.
  // Empty for a freshly-constructed session or one whose last stream has
  // since closed -- callers that need "do I have any active tunnel left"
  // should check this, not any single stream() accessor (removed: with
  // more than one stream possible, "the" stream no longer means anything).
  const absl::flat_hash_map<QuicStreamId, QuictunStream*>& streams() const {
    return streams_;
  }

  // Attaches/detaches the delegate that stream `id`'s events get forwarded
  // to. Must be set before that stream's traffic can be usefully acted
  // upon; events for a stream with no delegate attached are simply
  // dropped. `id` must currently be a live stream of this session.
  void SetStreamDelegate(QuicStreamId id, QuictunStreamDelegate* delegate) {
    stream_delegates_[id] = delegate;
  }

  // Invoked synchronously, exactly once per stream, the moment
  // CreateStream() actually creates it -- whether that's an incoming
  // stream (the server side, via CreateIncomingStream() below, itself
  // called synchronously by the QuicSession framework from inside
  // ProcessUdpPacket() no matter which socket delivered the packet -- see
  // QuictunServerConnection::MaybeStartTunnelForStream(), which used to
  // instead be re-polled ("has stream() gone non-null yet?") from several
  // different packet-delivery call sites and had one --
  // QuictunServerDriver's rendezvous-socket forwarding path -- that forgot
  // to poll it at all) or an outgoing one (the client side, via
  // OpenOutgoingStream(), called directly by its caller, which already
  // knows the stream now exists without needing this). Registering this is
  // the same idea as QuicSimpleServerSession wiring its own request-
  // handling logic directly into CreateIncomingStream()/the stream object
  // itself, rather than some external owner re-checking session state from
  // arbitrary call sites.
  void SetStreamCreatedCallback(std::function<void(QuicStreamId)> callback) {
    stream_created_callback_ = std::move(callback);
  }

 private:
  QuictunStream* CreateStream(QuicStreamId id);

  // QuictunStreamDelegate, implemented by forwarding to whichever delegate
  // (if any) is attached to the stream the event is actually for.
  void OnStreamDataAvailable(QuicStreamId id) override;
  void OnStreamCanWriteMore(QuicStreamId id) override;
  void OnStreamClosed(QuicStreamId id) override;

  std::string alpn_;
  absl::flat_hash_map<QuicStreamId, QuictunStream*> streams_;
  absl::flat_hash_map<QuicStreamId, QuictunStreamDelegate*> stream_delegates_;
  std::function<void(QuicStreamId)> stream_created_callback_;
};

class QUICHE_EXPORT QuictunClientSession final : public QuictunSessionBase {
 public:
  QuictunClientSession(QuicConnection* connection, Visitor* owner,
                        const QuicConfig& config, std::string alpn,
                        const QuicServerId& server_id,
                        QuicCryptoClientConfig* crypto_config);

  void CryptoConnect() { crypto_stream_->CryptoConnect(); }

  // Whether the server accepted this connection's 0-RTT early data (only
  // meaningful once the handshake has been confirmed).
  bool EarlyDataAccepted() const { return crypto_stream_->EarlyDataAccepted(); }

  // Diagnostic: why 0-RTT was or wasn't used (ssl_early_data_reason_t from
  // BoringSSL, e.g. ssl_early_data_no_session_offered if the client never
  // found a cached session to resume).
  ssl_early_data_reason_t EarlyDataReason() const {
    return crypto_stream_->EarlyDataReason();
  }

  // Invoked every time the client is (re-)allowed to open a new outgoing
  // bidirectional stream -- i.e. once QuicSession's own
  // ietf_streamid_manager_ has applied a max_streams value (from a 0-RTT
  // cache or the negotiated transport parameters) or the peer has raised
  // it further via a MAX_STREAMS frame. NOT the same moment as
  // QuicSession::Visitor::OnConfigNegotiated(): that visitor callback fires
  // from inside QuicSession::OnConfigNegotiated() *before* it updates
  // ietf_streamid_manager_ (see quic_session.cc), so retrying
  // OpenOutgoingStream() from there is one step too early and still fails.
  // The callback takes no arguments -- unlike SetStreamCreatedCallback(),
  // this isn't about any one stream, it's "you may now call
  // OpenOutgoingStream() again", and the caller (QuictunClientConnection)
  // is the one that knows whether it still has a pending TCP waiting for a
  // stream.
  void SetCanOpenStreamCallback(std::function<void()> callback) {
    can_open_stream_callback_ = std::move(callback);
  }

  // QuicSession:
  QuicCryptoStream* GetMutableCryptoStream() override {
    return crypto_stream_.get();
  }
  const QuicCryptoStream* GetCryptoStream() const override {
    return crypto_stream_.get();
  }

 protected:
  void OnCanCreateNewOutgoingStream(bool unidirectional) override {
    if (!unidirectional && can_open_stream_callback_) {
      can_open_stream_callback_();
    }
  }

 private:
  std::unique_ptr<QuicCryptoClientStream> crypto_stream_;
  std::function<void()> can_open_stream_callback_;
};

class QUICHE_EXPORT QuictunServerSession final : public QuictunSessionBase {
 public:
  QuictunServerSession(QuicConnection* connection, Visitor* owner,
                        const QuicConfig& config, std::string alpn,
                        const QuicCryptoServerConfig* crypto_config,
                        QuicCompressedCertsCache* compressed_certs_cache);

  // QuicSession:
  QuicCryptoStream* GetMutableCryptoStream() override {
    return crypto_stream_.get();
  }
  const QuicCryptoStream* GetCryptoStream() const override {
    return crypto_stream_.get();
  }

 private:
  std::unique_ptr<QuicCryptoServerStreamBase> crypto_stream_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_SESSION_H_
