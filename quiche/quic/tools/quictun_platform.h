// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// What quictun_client and quictun_server need from the operating system
// before anything else.

#ifndef QUICHE_QUIC_TOOLS_QUICTUN_PLATFORM_H_
#define QUICHE_QUIC_TOOLS_QUICTUN_PLATFORM_H_

#include "absl/status/status.h"

namespace quic {

// Called first thing in main(), before any socket exists. Per OS:
//   Linux    SIGPIPE ignored
//   macOS    SIGPIPE ignored; the open file limit raised
//   Windows  Winsock started; the Windows version checked; the system timer
//            at its finest period
// An error means quictun cannot run correctly on this system, and the
// binaries exit on it.
absl::Status InitQuictunPlatform();

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_PLATFORM_H_
