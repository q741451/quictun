// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// What quictun_client and quictun_server need from the operating system
// before anything else.

#ifndef QUICHE_QUIC_TOOLS_QUICTUN_PLATFORM_H_
#define QUICHE_QUIC_TOOLS_QUICTUN_PLATFORM_H_

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

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

// The account --user names.
struct QuictunRunAs {
  std::string name;
  uint32_t uid;
  uint32_t gid;
};

// Looks up what --user names: a user name, or a numeric uid. Meant to run
// before anything is bound, so that a mistyped user stops quictun before it
// listens rather than after. Returns nullopt when there is nothing to
// switch to: `user` is empty, or the process already runs as that user
// (which is how a service manager that starts it as that user looks).
// Otherwise the process must be root, and the user must have an entry in
// the passwd database, which supplies the primary group; a static binary
// reads /etc/passwd itself and consults no other directory service. On
// Windows any `user` is an error.
absl::StatusOr<std::optional<QuictunRunAs>> ResolveQuictunUser(
    absl::string_view user);

// Switches the process to `run_as`, its supplementary groups included, and
// prints what it now runs as. Called once the listening sockets are bound,
// the one thing quictun needs root for (a port below 1024): nothing after
// that does, including the client opening a new UDP socket to reconnect. A
// no-op for nullopt. An error leaves the process in an unknown state, so
// the caller must exit on it; success has been checked to be irreversible.
absl::Status DropToQuictunUser(const std::optional<QuictunRunAs>& run_as);

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_PLATFORM_H_
