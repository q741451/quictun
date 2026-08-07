// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_build_info.h"

#include "absl/strings/string_view.h"

namespace quic {

absl::string_view QuictunBuildTimestamp() {
  // __DATE__ expands to e.g. "Aug  6 2026" (note the double space before
  // single-digit days -- that's the standard's own formatting, not a typo
  // here), __TIME__ to e.g. "20:14:23".
  return __DATE__ " " __TIME__;
}

}  // namespace quic
