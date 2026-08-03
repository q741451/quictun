// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUICTUN_TUNNEL_ID_H_
#define QUICHE_QUICTUN_TUNNEL_ID_H_

#include <cstdint>
#include <cstring>
#include <optional>
#include <string>

#include "openssl/rand.h"
#include "absl/strings/string_view.h"

namespace quictun {

// Identifies one logical proxied-TCP-connection tunnel across however many
// underlying QUIC connections/streams it gets attached to over its lifetime
// (see autoexpire in quictun_client_bin.cc). Prefixed as the first
// kTunnelIdWireSize bytes of every stream that carries -- or continues --
// a tunnel, so the server can tell a brand new tunnel from a continuation of
// one it already has a TunnelPump for.
using TunnelId = uint64_t;

inline constexpr size_t kTunnelIdWireSize = sizeof(TunnelId);

inline TunnelId GenerateTunnelId() {
  TunnelId id;
  RAND_bytes(reinterpret_cast<uint8_t*>(&id), sizeof(id));
  return id;
}

inline void AppendTunnelId(TunnelId id, std::string* out) {
  for (int shift = (kTunnelIdWireSize - 1) * 8; shift >= 0; shift -= 8) {
    out->push_back(static_cast<char>((id >> shift) & 0xff));
  }
}

// Returns nullopt if `data` is shorter than kTunnelIdWireSize.
inline std::optional<TunnelId> ParseTunnelId(absl::string_view data) {
  if (data.size() < kTunnelIdWireSize) {
    return std::nullopt;
  }
  TunnelId id = 0;
  for (size_t i = 0; i < kTunnelIdWireSize; ++i) {
    id = (id << 8) | static_cast<uint8_t>(data[i]);
  }
  return id;
}

}  // namespace quictun

#endif  // QUICHE_QUICTUN_TUNNEL_ID_H_
