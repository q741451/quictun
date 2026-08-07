// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A non-HTTP QUIC session/stream pair for quictun: exactly one bidirectional
// QUIC stream carries one TCP connection's raw byte stream, with no HTTP/3
// or WebTransport framing on top. This deliberately does not build on
// QuicGenericSessionBase (quic_generic_session.h): that class exists to
// expose a full WebTransport session (datagrams, multi-stream accept
// queues, stream priorities), none of which quictun needs.

#ifndef QUICHE_QUIC_TOOLS_QUICTUN_SESSION_H_
#define QUICHE_QUIC_TOOLS_QUICTUN_SESSION_H_

#include <functional>
#include <memory>
#include <string>
#include <vector>

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

// Receives events from the tunnel's one QuictunStream. Implemented by
// QuictunTunnel (see quictun_tunnel.h); QuictunSessionBase itself implements
// this interface too and forwards to whichever delegate has been attached,
// so stream events that arrive before a tunnel exists are simply dropped.
class QUICHE_EXPORT QuictunStreamDelegate {
 public:
  virtual ~QuictunStreamDelegate() = default;

  // New bytes are readable on the stream (or the peer's FIN is readable).
  // The delegate should call QuictunStream::Read() to consume them.
  virtual void OnStreamDataAvailable() = 0;

  // The stream can accept more written data after being write-blocked.
  virtual void OnStreamCanWriteMore() = 0;

  // The stream has closed (FIN both ways, reset, or the connection closed).
  // The delegate must not touch the stream afterward.
  virtual void OnStreamClosed() = 0;
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
// "h3"), exactly one stream ever created, and forwarding of that stream's
// events to whatever QuictunStreamDelegate has been attached.
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

  // Opens the tunnel's one outgoing stream. Only ever called once, by
  // whichever side is responsible for starting the tunnel (currently always
  // the client -- see quictun_client_connection.cc). Safe to call
  // immediately after CryptoConnect(), even before the handshake is
  // confirmed: if a 0-RTT session is available, QuicStream buffers/sends the
  // data at whatever encryption level is ready, same as any other 0-RTT
  // QUIC client (e.g. QuicSpdyClientBase).
  QuictunStream* OpenOutgoingStream();

  QuictunStream* stream() const { return stream_; }

  // Attaches/detaches the delegate that stream events get forwarded to.
  // Must be set before any tunnel traffic can be usefully acted upon; events
  // that arrive with no delegate attached are simply dropped.
  void SetStreamDelegate(QuictunStreamDelegate* delegate) {
    stream_delegate_ = delegate;
  }

 private:
  QuictunStream* CreateStream(QuicStreamId id);

  // QuictunStreamDelegate, implemented by forwarding to stream_delegate_.
  void OnStreamDataAvailable() override;
  void OnStreamCanWriteMore() override;
  void OnStreamClosed() override;

  std::string alpn_;
  QuictunStream* stream_ = nullptr;
  QuictunStreamDelegate* stream_delegate_ = nullptr;
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

  // Invoked once the client is actually allowed to open a new outgoing
  // bidirectional stream -- i.e. once QuicSession's own
  // ietf_streamid_manager_ has applied a max_streams value (from a 0-RTT
  // cache or the negotiated transport parameters). NOT the same moment as
  // QuicSession::Visitor::OnConfigNegotiated(): that visitor callback fires
  // from inside QuicSession::OnConfigNegotiated() *before* it updates
  // ietf_streamid_manager_ (see quic_session.cc), so retrying
  // OpenOutgoingStream() from there is one step too early and still fails.
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
