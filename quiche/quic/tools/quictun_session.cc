// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_session.h"

#include <cstddef>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/quic_crypto_client_stream.h"
#include "quiche/quic/core/quic_crypto_server_stream_base.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_stream_sequencer.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace quic {

namespace {

// quictun does not use TLS client certificates or channel IDs; this proof
// handler mirrors the no-op one used by QuicGenericClientSession
// (quic_generic_session.cc) for the same reason -- the real authentication
// boundary is the pre-shared key (see quictun_certificate.h), not the
// server's certificate chain, which the client doesn't validate at all.
class NoOpProofHandler : public QuicCryptoClientStream::ProofHandler {
 public:
  void OnProofValid(const QuicCryptoClientConfig::CachedState&) override {}
  void OnProofVerifyDetailsAvailable(const ProofVerifyDetails&) override {}
  bool OnCertificateRequested(
      const std::vector<std::string>& /*cert_authorities*/) override {
    return false;
  }
};

// quictun's own authentication is the pre-shared key checked by the TLS 1.3
// handshake itself; there is no separate application-level policy to apply
// to the ClientHello, so accept unconditionally (same reasoning as
// QuicGenericServerSession's NoOpServerCryptoHelper).
class NoOpServerCryptoHelper : public QuicCryptoServerStreamBase::Helper {
 public:
  bool CanAcceptClientHello(const CryptoHandshakeMessage& /*message*/,
                            const QuicSocketAddress& /*client_address*/,
                            const QuicSocketAddress& /*peer_address*/,
                            const QuicSocketAddress& /*self_address*/,
                            std::string* /*error_details*/) const override {
    return true;
  }
};

}  // namespace

ParsedQuicVersionVector GetQuictunVersions() {
  return {ParsedQuicVersion::RFCv1()};
}

QuictunStream::QuictunStream(QuicStreamId id, QuicSession* session,
                             QuictunStreamDelegate* delegate)
    : QuicStream(id, session, /*is_static=*/false,
                 QuicUtils::GetStreamType(id, session->connection()->perspective(),
                                          session->IsIncomingStream(id),
                                          session->version())),
      delegate_(delegate) {
  sequencer()->set_level_triggered(true);
}

void QuictunStream::OnDataAvailable() {
  const bool fin_readable = sequencer()->IsClosed();
  if (sequencer()->ReadableBytes() == 0 && !fin_readable) {
    return;
  }
  delegate_->OnStreamDataAvailable();
}

void QuictunStream::OnCanWriteNewData() {
  if (!CanWriteNewData()) {
    return;
  }
  delegate_->OnStreamCanWriteMore();
}

void QuictunStream::OnClose() {
  QuicStream::OnClose();
  delegate_->OnStreamClosed();
}

size_t QuictunStream::Read(absl::Span<char> buffer, bool* fin) {
  iovec iov;
  iov.iov_base = buffer.data();
  iov.iov_len = buffer.size();
  const size_t bytes_read = sequencer()->Readv(&iov, 1);
  *fin = sequencer()->IsClosed();
  if (*fin) {
    OnFinRead();
  }
  return bytes_read;
}

void QuictunStream::WriteToStream(absl::string_view data, bool fin) {
  WriteOrBufferData(data, fin, /*ack_listener=*/nullptr);
}

QuicConnection* QuictunStream::connection() { return session()->connection(); }

bool QuictunStream::CanBufferMoreWrites() const {
  // Previously also capped BufferedDataBytes() at a hardcoded 256 KB on top
  // of this -- tighter than the (independently configurable, see
  // quictun_flags.h) QUIC-level flow-control window on any path with a
  // window larger than that, making the hardcoded cap the actual
  // throughput ceiling instead of the window an operator explicitly set.
  // main's own TunnelPump (quiche/quictun/tunnel_pump.cc) and QUICHE's own
  // reference connect_tunnel.cc both rely on nothing more than the
  // underlying stream's own write-availability check, so do the same here.
  return CanWriteNewData();
}

QuictunSessionBase::QuictunSessionBase(QuicConnection* connection,
                                       Visitor* owner, const QuicConfig& config,
                                       std::string alpn)
    : QuicSession(connection, owner, config, GetQuictunVersions(),
                  /*num_expected_unidirectional_static_streams=*/0),
      alpn_(std::move(alpn)) {}

std::vector<std::string> QuictunSessionBase::GetAlpnsToOffer() const {
  return {alpn_};
}

std::vector<absl::string_view>::const_iterator
QuictunSessionBase::SelectAlpn(
    const std::vector<absl::string_view>& alpns) const {
  return absl::c_find(alpns, alpn_);
}

void QuictunSessionBase::OnAlpnSelected(absl::string_view alpn) {
  QUICHE_DCHECK_EQ(alpn, alpn_);
}

QuicStream* QuictunSessionBase::CreateIncomingStream(QuicStreamId id) {
  if (stream_ != nullptr) {
    // quictun is strictly one stream per connection; anything more is
    // either a misbehaving peer or a protocol bug on our own side.
    connection()->CloseConnection(
        QUIC_TOO_MANY_OPEN_STREAMS,
        "quictun only ever uses a single stream per connection",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return nullptr;
  }
  return CreateStream(id);
}

QuictunStream* QuictunSessionBase::OpenOutgoingStream() {
  QUICHE_DCHECK(stream_ == nullptr);
  if (!CanOpenNextOutgoingBidirectionalStream()) {
    // Expected, not a bug: with no cached 0-RTT session, a client can't
    // open its stream until it has received the peer's transport
    // parameters (i.e. after the handshake round trip completes) -- the
    // caller is expected to retry from QuicSession::Visitor::
    // OnConfigNegotiated(). See QuictunClientConnection.
    return nullptr;
  }
  return CreateStream(GetNextOutgoingBidirectionalStreamId());
}

QuictunStream* QuictunSessionBase::CreateStream(QuicStreamId id) {
  auto stream = std::make_unique<QuictunStream>(id, this, this);
  QuictunStream* stream_ptr = stream.get();
  stream_ = stream_ptr;
  ActivateStream(std::move(stream));
  return stream_ptr;
}

void QuictunSessionBase::OnStreamDataAvailable() {
  if (stream_delegate_ != nullptr) {
    stream_delegate_->OnStreamDataAvailable();
  }
}

void QuictunSessionBase::OnStreamCanWriteMore() {
  if (stream_delegate_ != nullptr) {
    stream_delegate_->OnStreamCanWriteMore();
  }
}

void QuictunSessionBase::OnStreamClosed() {
  if (stream_delegate_ != nullptr) {
    stream_delegate_->OnStreamClosed();
  }
}

QuictunClientSession::QuictunClientSession(QuicConnection* connection,
                                           Visitor* owner,
                                           const QuicConfig& config,
                                           std::string alpn,
                                           const QuicServerId& server_id,
                                           QuicCryptoClientConfig* crypto_config)
    : QuictunSessionBase(connection, owner, config, std::move(alpn)) {
  static NoOpProofHandler* handler = new NoOpProofHandler();
  crypto_stream_ = std::make_unique<QuicCryptoClientStream>(
      server_id, this, crypto_config->proof_verifier()->CreateDefaultContext(),
      crypto_config, /*proof_handler=*/handler,
      /*has_application_state=*/false);
}

QuictunServerSession::QuictunServerSession(
    QuicConnection* connection, Visitor* owner, const QuicConfig& config,
    std::string alpn, const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache)
    : QuictunSessionBase(connection, owner, config, std::move(alpn)) {
  static NoOpServerCryptoHelper* helper = new NoOpServerCryptoHelper();
  crypto_stream_ = CreateCryptoServerStream(crypto_config,
                                            compressed_certs_cache, this,
                                            helper);
  // Required for 0-RTT: QuicCryptoStream::SetServerApplicationStateForResumption's
  // doc comment is explicit that "this function must be called before
  // commencing the handshake, otherwise 0-RTT tickets will not be issued"
  // (it's what makes TlsServerHandshaker call SSL_set_quic_early_data_context,
  // which BoringSSL requires before it will mark an issued session ticket as
  // early-data-capable at all). HTTP/3 sessions pass their serialized
  // SETTINGS frame here (see QuicServerSessionBase::OnSettingsFrame); quictun
  // has no equivalent application-layer state, so an empty (but non-null)
  // ApplicationState is enough to satisfy the requirement -- it still acts
  // as this server's stable "protocol version tag" for 0-RTT tickets.
  crypto_stream_->SetServerApplicationStateForResumption(
      std::make_unique<ApplicationState>());
}

}  // namespace quic
