// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// What quictun_client and quictun_server need from the operating system
// before anything else.

#ifndef QUICHE_QUIC_TOOLS_QUICTUN_PLATFORM_H_
#define QUICHE_QUIC_TOOLS_QUICTUN_PLATFORM_H_

#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"

namespace quic {

// Called first thing in main(), before any socket exists. Per OS:
//   Linux    SIGPIPE ignored
//   macOS    SIGPIPE ignored; the open file limit raised
//   Windows  Winsock started; the Windows version checked; the system timer
//            at its finest period
// An error means quictun cannot run correctly on this system, and the
// binaries exit on it.
absl::Status InitQuictunPlatform();

// The command line, as UTF-8, to parse flags from instead of main()'s argv.
// Linux and macOS hand main() the bytes typed; Windows hands it argv in the
// ANSI code page, which turns whatever that page lacks into '?' -- so a
// non-ASCII --key would derive a different key there than on the other end,
// and different keys could collapse into one. On Windows the arguments are
// rebuilt from GetCommandLineW() instead, as Chromium's base::CommandLine
// does. An error means the command line could not be read.
absl::StatusOr<std::vector<std::string>> QuictunCommandLine(int argc,
                                                            char* argv[]);

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_PLATFORM_H_
