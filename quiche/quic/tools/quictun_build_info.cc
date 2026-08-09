// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_build_info.h"

#include "absl/strings/string_view.h"
#include "quiche/quic/tools/quictun_build_timestamp.h"

namespace quic {

absl::string_view QuictunBuildTimestamp() {
  // See this function's declaration (quictun_build_info.h) for why
  // QUICTUN_BUILD_TIMESTAMP comes from an externally-regenerated header
  // rather than __DATE__/__TIME__ or a Bazel-native stamping mechanism.
  return QUICTUN_BUILD_TIMESTAMP;
}

}  // namespace quic
