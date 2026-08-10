// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A SessionCache that hands the same cached 0-RTT ticket out to as many
// concurrent connection attempts as ask for it, instead of the stock
// QuicClientSessionCache's give-it-out-once-then-delete-it default (see
// that class's Lookup() doc comment in quic_crypto_client_config.h:
// "Implementations should delete cache entries after returning them ... so
// that session tickets are used only once" -- a deliberate, documented
// recommendation this class knowingly does not follow).
//
// Why: quictun_client can open many concurrent QUIC connections to the same
// --remote in a burst (one per accepted local TCP connection). A TLS 1.3
// server typically hands out only 1-2 usable tickets per handshake
// (BoringSSL's default), and QuicClientSessionCache deletes each ticket the
// moment any connection looks it up -- so with a burst of N concurrent
// connections, only the first 1-2 ever get to use 0-RTT; the rest silently
// fall back to a full handshake (one extra round trip -- ~300ms+ on a real
// path like the one that motivated this class).
//
// The trade this makes explicit: TLS 1.3's per-ticket usage tracking is one
// input to 0-RTT replay defense (a network observer who captures one 0-RTT
// ClientHello can, in principle, replay it against a server that itself
// implements anti-replay checks). quictun's own deployment doesn't need
// that defense -- servers that DO implement their own 0-RTT anti-replay
// would simply reject the repeated ticket the same way they'd reject any
// other 0-RTT attempt they're unhappy with, which this client already
// handles by falling back to a normal handshake; this class doesn't break
// compatibility with such servers, it just stops helping quictun's own
// tunnel scenario against one.
//
// Deliberately NOT a thin override of QuicClientSessionCache::Lookup() that
// pops-then-immediately-re-Inserts a duplicate: that approach was tried
// first and works, but its correctness leans on an *implementation detail*
// of QuicClientSessionCache::Insert() that isn't part of SessionCache's
// documented contract -- specifically, that re-inserting a session with
// identical params/application_state takes Insert()'s "just push onto the
// existing entry" branch rather than its "erase and recreate the entry"
// branch (see quic_client_session_cache.cc). That's an internal branch
// choice of a class this code doesn't own; a future upstream change to it
// could silently degrade this cache back toward single-use with no direct
// signal beyond "0-RTT stops getting reused as often". This class instead
// owns its one piece of state directly and reuses only the one real,
// interface-documented BoringSSL primitive the whole scheme depends on --
// bssl::UpRef() (SSL_SESSION's own reference count) -- so every line of
// its actual behavior is under this file's control, not inferred from
// another class's internals.
//
// Deliberately much simpler than QuicClientSessionCache in the same spirit,
// though: quictun_client is always configured with exactly one --remote for
// its whole process lifetime, so there is only ever one QuicServerId this
// cache will ever be asked about -- no need for QuicClientSessionCache's
// own multi-server QuicLRUCache<QuicServerId, Entry> machinery, or its
// 2-ticket-per-server backup slot (that slot exists to give a *pop*-based
// cache a second ticket to fall back to; a *peek*-based cache like this one
// never runs out on its own, so there's nothing to back up).
#ifndef QUICHE_QUIC_TOOLS_QUICTUN_REUSABLE_SESSION_CACHE_H_
#define QUICHE_QUIC_TOOLS_QUICTUN_REUSABLE_SESSION_CACHE_H_

#include <memory>
#include <optional>
#include <string>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/quic_crypto_client_config.h"
#include "quiche/quic/core/quic_server_id.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_export.h"

namespace quic {

class QUICHE_EXPORT QuictunReusableSessionCache final : public SessionCache {
 public:
  QuictunReusableSessionCache();
  ~QuictunReusableSessionCache() override;

  // SessionCache:
  void Insert(const QuicServerId& server_id,
              bssl::UniquePtr<SSL_SESSION> session,
              const TransportParameters& params,
              const ApplicationState* application_state) override;
  std::unique_ptr<QuicResumptionState> Lookup(const QuicServerId& server_id,
                                              QuicWallTime now,
                                              const SSL_CTX* ctx) override;
  void ClearEarlyData(const QuicServerId& server_id) override;
  void OnNewTokenReceived(const QuicServerId& server_id,
                          absl::string_view token) override;
  void RemoveExpiredEntries(QuicWallTime now) override;
  void Clear() override;
  size_t GetSize() const override;
  size_t GetMaxSize() const override;
  void UpdateMaxSize(size_t max_entries) override;

 private:
  // Set on the first Insert()/Lookup() and checked (debug-only) against on
  // every later call -- documents and enforces the single-server-per-
  // process assumption above rather than silently misbehaving if it's ever
  // violated (e.g. a future quictun_client feature that reconnects to a
  // different --remote while reusing the same crypto_config).
  std::optional<QuicServerId> server_id_;

  bssl::UniquePtr<SSL_SESSION> session_;
  std::unique_ptr<TransportParameters> params_;
  std::unique_ptr<ApplicationState> application_state_;
  std::string token_;  // Opaque NEW_TOKEN value; single-use, unrelated to
                       // the 0-RTT ticket reuse this class is about -- see
                       // Lookup()'s comment on why this one still clears.
};

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_REUSABLE_SESSION_CACHE_H_
