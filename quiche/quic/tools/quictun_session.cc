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
#include "quiche/quic/core/quic_stream_priority.h"
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
  // incremental=true, not the RFC 9218 default (false): a quictun stream is
  // raw TCP bytes arriving continuously for as long as the tunnel lives --
  // there's no "whole resource" that only becomes useful once fully
  // delivered (what incremental=false/HTTP's default is actually for, e.g.
  // a page's critical CSS/JS) -- matching the intent RFC 9218 defines this
  // field for, the same way real QUICHE's own WebTransportStreamAdapter
  // sidesteps this same "arbitrary continuous byte stream" question
  // entirely with its own non-HTTP priority scheme. A correctness/intent
  // fix on its own merits, kept even though it turned out NOT to be what
  // actually mattered for a real, reproduced --quic_conn pooling stall
  // (some streams enqueued into write_blocked_streams_ exactly once and
  // never dequeued again): QuicWriteBlockedList only actually looks at
  // this field when --quic_priority_respect_incremental is enabled, which
  // it isn't here by default, so this alone changes no runtime behavior
  // today. See quictun_tunnel.cc's BeginReadFromTcp()/ReceiveComplete()
  // for the change that actually fixed that stall.
  SetPriority(QuicStreamPriority(
      HttpStreamPriority{HttpStreamPriority::kDefaultUrgency,
                         /*incremental=*/true}));
}

void QuictunStream::OnDataAvailable() {
  const bool fin_readable = sequencer()->IsClosed();
  if (sequencer()->ReadableBytes() == 0 && !fin_readable) {
    return;
  }
  delegate_->OnStreamDataAvailable(id());
}

void QuictunStream::OnCanWriteNewData() {
  if (!CanWriteNewData()) {
    return;
  }
  delegate_->OnStreamCanWriteMore(id());
}

void QuictunStream::OnClose() {
  QuicStream::OnClose();
  delegate_->OnStreamGone(id());
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
  // No cap here beyond what the QuicSession framework itself already
  // enforces before ever calling this (a peer that tries to exceed the
  // max_streams value this side advertised gets rejected at a lower layer,
  // in GetOrCreateStream() -- CreateIncomingStream() is simply never
  // invoked for an over-limit stream id). Per-connection stream count
  // policy (--quic_conn) lives in QuictunClientConnection, on the side
  // that actually decides to open new streams; the server side is purely
  // reactive to however many streams a client legitimately opens.
  return CreateStream(id);
}

QuictunStream* QuictunSessionBase::OpenOutgoingStream() {
  if (!CanOpenNextOutgoingBidirectionalStream()) {
    // Expected, not a bug: with no cached 0-RTT session, a client can't
    // open a stream until it has received the peer's transport parameters
    // (i.e. after the handshake round trip completes) -- the caller is
    // expected to retry from SetCanOpenStreamCallback(). See
    // QuictunClientConnection.
    return nullptr;
  }
  return CreateStream(GetNextOutgoingBidirectionalStreamId());
}

QuictunStream* QuictunSessionBase::CreateStream(QuicStreamId id) {
  auto stream = std::make_unique<QuictunStream>(id, this, this);
  QuictunStream* stream_ptr = stream.get();
  streams_[id] = stream_ptr;
  ActivateStream(std::move(stream));
  // Notify after the stream is fully activated (present in the session's own
  // stream map, so anything the callback does -- e.g. SetStreamDelegate(),
  // stream->Read() -- sees consistent state), but still synchronously
  // within whatever caused this stream to be created, exactly once. See the
  // comment on SetStreamCreatedCallback() for why this exists.
  if (stream_created_callback_) {
    stream_created_callback_(id);
  }
  return stream_ptr;
}

void QuictunSessionBase::OnStreamDataAvailable(QuicStreamId id) {
  auto it = stream_delegates_.find(id);
  if (it != stream_delegates_.end() && it->second != nullptr) {
    it->second->OnStreamDataAvailable(id);
  }
}

void QuictunSessionBase::OnStreamCanWriteMore(QuicStreamId id) {
  auto it = stream_delegates_.find(id);
  if (it != stream_delegates_.end() && it->second != nullptr) {
    it->second->OnStreamCanWriteMore(id);
  }
}

void QuictunSessionBase::OnStreamGone(QuicStreamId id) {
  auto it = stream_delegates_.find(id);
  if (it != stream_delegates_.end()) {
    QuictunStreamDelegate* delegate = it->second;
    // Erase before notifying: this stream is gone either way, and the
    // delegate's own OnStreamGone() is exactly the kind of place that
    // might turn around and query streams()/try to detach itself again.
    stream_delegates_.erase(it);
    streams_.erase(id);
    if (delegate != nullptr) {
      delegate->OnStreamGone(id);
    }
  } else {
    streams_.erase(id);
  }
}

QuictunClientSession::QuictunClientSession(QuicConnection* connection,
                                           Visitor* owner,
                                           const QuicConfig& config,
                                           std::string alpn,
                                           const QuicServerId& server_id,
                                           QuicCryptoClientConfig* crypto_config,
                                           bool poolable)
    : QuictunSessionBase(connection, owner, config, std::move(alpn)),
      poolable_(poolable) {
  static NoOpProofHandler* handler = new NoOpProofHandler();
  crypto_stream_ = std::make_unique<QuicCryptoClientStream>(
      server_id, this, crypto_config->proof_verifier()->CreateDefaultContext(),
      crypto_config, /*proof_handler=*/handler,
      /*has_application_state=*/false);
  // See ever_had_stream_'s comment/ShouldKeepConnectionAlive(). Internal to
  // this class -- QuictunClientConnection doesn't use
  // SetStreamCreatedCallback() itself, so this doesn't collide with
  // anything an owner might also want to set here.
  SetStreamCreatedCallback(
      [this](QuicStreamId /*id*/) { ever_had_stream_ = true; });
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
