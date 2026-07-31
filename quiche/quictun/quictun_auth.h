// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUICTUN_QUICTUN_AUTH_H_
#define QUICHE_QUICTUN_QUICTUN_AUTH_H_

#include <string>

#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "openssl/crypto.h"
#include "openssl/hmac.h"
#include "openssl/sha.h"

namespace quictun {

// Name of the HTTP header carrying the pre-shared-key auth token on the
// WebTransport CONNECT request. This is quictun's equivalent of kcptun's
// --key: QUIC/TLS 1.3 already encrypts and authenticates the wire traffic,
// so this token exists purely to keep random UDP scanners from opening
// tunnels through an exposed quictun-server, not to replace TLS.
inline constexpr absl::string_view kAuthHeader = "x-quictun-auth";

// A fixed context string mixed into the HMAC so the token is specific to
// quictun rather than reusable for anything else derived from the same key.
inline constexpr absl::string_view kAuthContext = "quictun-auth-v1";

// Derives the auth token for pre-shared key `key`: hex(HMAC-SHA256(key,
// kAuthContext)). Deliberately static (no per-connection nonce), matching
// kcptun's own model where the same shared key is used to key every
// session identically.
inline std::string ComputeAuthToken(absl::string_view key) {
  unsigned char digest[SHA256_DIGEST_LENGTH];
  unsigned int digest_len = 0;
  HMAC(EVP_sha256(), key.data(), key.size(),
       reinterpret_cast<const unsigned char*>(kAuthContext.data()),
       kAuthContext.size(), digest, &digest_len);
  return absl::BytesToHexString(
      absl::string_view(reinterpret_cast<const char*>(digest), digest_len));
}

// Constant-time comparison for the auth token, to avoid leaking how many
// leading bytes matched via response-time side channels.
inline bool ConstantTimeEquals(absl::string_view a, absl::string_view b) {
  if (a.size() != b.size()) return false;
  return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

}  // namespace quictun

#endif  // QUICHE_QUICTUN_QUICTUN_AUTH_H_
