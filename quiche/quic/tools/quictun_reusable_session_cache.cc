// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_reusable_session_cache.h"

#include <utility>

#include "openssl/ssl.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace quic {

namespace {

// Same freshness check as the free function IsValid() in
// quic_client_session_cache.cc: SSL_SESSION_get_time()/get_timeout() are
// exactly what the server put in the ticket's lifetime field (see
// BoringSSL's tls13_server.cc), so this reads back the real, negotiated
// expiry -- not a locally-invented one.
bool IsSessionStillValid(SSL_SESSION* session, uint64_t now) {
  if (session == nullptr) return false;
  return !(now + 1 < SSL_SESSION_get_time(session) ||
           now >= SSL_SESSION_get_time(session) +
                      SSL_SESSION_get_timeout(session));
}

}  // namespace

QuictunReusableSessionCache::QuictunReusableSessionCache() = default;
QuictunReusableSessionCache::~QuictunReusableSessionCache() = default;

void QuictunReusableSessionCache::Insert(
    const QuicServerId& server_id, bssl::UniquePtr<SSL_SESSION> session,
    const TransportParameters& params,
    const ApplicationState* application_state) {
  QUICHE_DCHECK(!server_id_.has_value() || server_id_.value() == server_id)
      << "QuictunReusableSessionCache assumes a single server_id for its "
         "whole process lifetime, saw ("
      << server_id_->host() << ":" << server_id_->port() << ") then ("
      << server_id.host() << ":" << server_id.port() << ")";
  server_id_ = server_id;

  // Multiple sessions can be inserted for one connection (TLS 1.3 servers
  // commonly send 2 NewSessionTickets) -- QuicClientSessionCache keeps both
  // as a backup pair for its pop-once semantics; this cache only ever needs
  // "the latest one", so each Insert() just replaces what's there. Whatever
  // was previously cached simply stops being handed out to new Lookup()s;
  // any connection that already up-ref'd it keeps its own reference alive
  // for exactly as long as it's using it.
  session_ = std::move(session);
  params_ = std::make_unique<TransportParameters>(params);
  application_state_ = application_state != nullptr
                            ? std::make_unique<ApplicationState>(*application_state)
                            : nullptr;
}

std::unique_ptr<QuicResumptionState> QuictunReusableSessionCache::Lookup(
    const QuicServerId& server_id, QuicWallTime now, const SSL_CTX* /*ctx*/) {
  if (session_ == nullptr) {
    return nullptr;
  }
  QUICHE_DCHECK(!server_id_.has_value() || server_id_.value() == server_id)
      << "QuictunReusableSessionCache assumes a single server_id for its "
         "whole process lifetime, saw ("
      << server_id_->host() << ":" << server_id_->port() << ") then ("
      << server_id.host() << ":" << server_id.port() << ")";

  if (!IsSessionStillValid(session_.get(), now.ToUNIXSeconds())) {
    QUIC_DLOG(INFO) << "TLS Session expired for host:" << server_id.host();
    session_ = nullptr;
    params_ = nullptr;
    application_state_ = nullptr;
    return nullptr;
  }

  auto state = std::make_unique<QuicResumptionState>();
  // The one line that actually makes this cache reusable instead of
  // single-use: UpRef() bumps SSL_SESSION's own internal refcount and hands
  // back a new, independently-owned bssl::UniquePtr pointing at the same
  // underlying ticket -- session_ itself is untouched, so any number of
  // concurrent Lookup() calls can each walk away with their own live
  // reference to it. Compare QuicClientSessionCache::Lookup(), which
  // std::move()s (and thus empties) its stored session on every call.
  state->tls_session = bssl::UpRef(session_);
  if (params_ != nullptr) {
    state->transport_params = std::make_unique<TransportParameters>(*params_);
  }
  if (application_state_ != nullptr) {
    state->application_state =
        std::make_unique<ApplicationState>(*application_state_);
  }
  if (!token_.empty()) {
    // Unlike the ticket above, the NEW_TOKEN address-validation token keeps
    // QuicClientSessionCache's original single-use behavior: it's a
    // different mechanism (skips an extra address-validation round trip on
    // a future Initial, not 0-RTT application data) that wasn't part of
    // what this class's reuse trade-off was scoped to cover.
    state->token = token_;
    token_.clear();
  }
  return state;
}

void QuictunReusableSessionCache::ClearEarlyData(
    const QuicServerId& /*server_id*/) {
  if (session_ == nullptr) {
    return;
  }
  // Matches QuicClientSessionCache::ClearEarlyData(): replace the cached
  // session with an early-data-disabled copy so any *future* Lookup() (and
  // thus any new connection that hasn't started yet) won't attempt 0-RTT
  // with it, without touching connections that already up-ref'd the
  // original and may still be mid-handshake with it.
  session_.reset(SSL_SESSION_copy_without_early_data(session_.get()));
}

void QuictunReusableSessionCache::OnNewTokenReceived(
    const QuicServerId& /*server_id*/, absl::string_view token) {
  if (token.empty()) {
    return;
  }
  token_ = std::string(token);
}

void QuictunReusableSessionCache::RemoveExpiredEntries(QuicWallTime now) {
  if (session_ != nullptr &&
      !IsSessionStillValid(session_.get(), now.ToUNIXSeconds())) {
    session_ = nullptr;
    params_ = nullptr;
    application_state_ = nullptr;
  }
}

void QuictunReusableSessionCache::Clear() {
  session_ = nullptr;
  params_ = nullptr;
  application_state_ = nullptr;
  token_.clear();
}

size_t QuictunReusableSessionCache::GetSize() const {
  return session_ != nullptr ? 1 : 0;
}

size_t QuictunReusableSessionCache::GetMaxSize() const { return 1; }

void QuictunReusableSessionCache::UpdateMaxSize(size_t /*max_entries*/) {
  // Fixed at one entry (see the class comment) -- nothing to update.
  // quictun never calls this; it exists only because SessionCache requires
  // an implementation.
}

}  // namespace quic
