// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_TOOLS_QUICTUN_BUILD_INFO_H_
#define QUICHE_QUIC_TOOLS_QUICTUN_BUILD_INFO_H_

#include "absl/strings/string_view.h"

namespace quic {

// This binary's compile date/time, e.g. "2026/08/06 20:14:23" (the build
// machine's local time). Printed once at startup by
// PrintQuictunStartupBanner() (quictun_flags.h) so operators can tell which
// build is actually running without cross-referencing a git hash against CI
// logs.
//
// Sourced from quic/tools/quictun_build_timestamp.h, NOT the preprocessor's
// __DATE__/__TIME__ macros this file used to use directly -- those look
// non-hermetic but Bazel's action cache has no way to know that, so a
// plain __DATE__/__TIME__ here would silently freeze at whenever this file
// last happened to actually recompile, not the current build. That header
// isn't a checked-in file or a Bazel-generated target either: it's
// (re)written with the real current time by
// build/regen_quictun_build_timestamp.sh immediately before every `bazel
// build` (see that script and .github/workflows/build.yml for the CI
// usage). Two Bazel-native alternatives were tried and both failed to
// actually take effect: Bazel's own documentation states outright that
// stamped actions (genrule(stamp = 1) and friends, reading
// bazel-out/volatile-status.txt) are deliberately NOT rerun just because
// the volatile status file's contents changed -- "Bazel pretends that the
// volatile file never changes", precisely to avoid rerunning stamped
// actions on every single build. That's fundamentally incompatible with
// wanting a timestamp that's actually fresh on every build regardless of
// what else changed, which is exactly why this needs an external script
// instead: a plain source file Bazel sees as genuinely changed (via its
// own ordinary, well-understood hermetic caching, not the volatile-status
// exemption) needs no special-cased Bazel behavior to work correctly.
absl::string_view QuictunBuildTimestamp();

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_BUILD_INFO_H_
