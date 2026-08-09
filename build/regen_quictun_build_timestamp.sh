#!/bin/bash
# Copyright 2026 The quictun Authors.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# (Re)writes quiche/quic/tools/quictun_build_timestamp.h with the current
# time -- run this before every `bazel build` that should show a real,
# current build timestamp in quictun's startup banner (both CI and local
# dev builds; see .github/workflows/build.yml for the CI usage).
#
# Not a Bazel target: two attempts at making Bazel itself regenerate this
# file fresh on every build (a genrule reading $(BUILD_TIMESTAMP), and a
# custom rule reading ctx.version_file with a no-cache execution
# requirement) both failed to actually take effect in practice -- Bazel
# kept reusing a stale, already-cached copy of the header even though the
# file this script writes now (not through Bazel) genuinely changes every
# run, sidestepping needing either of those to work correctly. See
# quiche/quic/tools/quictun_build_info.cc's own comment.
set -eu
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# LC_TIME=C: keep this locale-independent regardless of the build
# machine's own locale (this used to be __DATE__/__TIME__, always-English
# -- see quictun_build_info.h). yyyy/mm/dd hh:mm:ss: sorts correctly as
# plain text and reads unambiguously (no "Aug" vs "8月" vs "08" guessing).
printf '#define QUICTUN_BUILD_TIMESTAMP "%s"\n' \
    "$(LC_TIME=C date '+%Y/%m/%d %H:%M:%S')" \
    > quiche/quic/tools/quictun_build_timestamp.h
