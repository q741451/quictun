// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_TOOLS_QUICTUN_BUILD_INFO_H_
#define QUICHE_QUIC_TOOLS_QUICTUN_BUILD_INFO_H_

#include "absl/strings/string_view.h"

namespace quic {

// This binary's compile date/time, e.g. "Aug  6 2026 20:14:23" (the build
// machine's local time, straight from the preprocessor's __DATE__/__TIME__).
// Printed once at startup by PrintQuictunStartupBanner() (quictun_flags.h)
// so operators can tell which build is actually running without cross-
// referencing a git hash against CI logs.
//
// Deliberately isolated in its own translation unit (quictun_build_info.cc)
// rather than expanded here in the header: __DATE__/__TIME__ make whichever
// .o they appear in non-hermetic (its content depends on wall-clock time,
// not just its inputs), which defeats Bazel's action cache for that file.
// Confining that to one tiny, rarely-touched file keeps the rest of
// quictun's object files cacheable as normal.
absl::string_view QuictunBuildTimestamp();

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_BUILD_INFO_H_
