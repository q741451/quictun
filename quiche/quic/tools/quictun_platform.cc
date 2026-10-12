// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_platform.h"

#include <cerrno>
#include <csignal>
#if defined(__APPLE__)
#include <sys/resource.h>
#include <sys/sysctl.h>
#endif

#include "absl/status/status.h"

namespace quic {

namespace {

absl::Status IgnoreSigpipe() {
  // quic::socket_api::Send() (quic/core/io/socket.cc) is a bare ::send()
  // with no MSG_NOSIGNAL, so writing to a tunneled TCP socket -- the
  // client's --local one, the server's --target one -- after its peer
  // already reset the connection, routine whenever a download being
  // tunneled gets cancelled, delivers SIGPIPE. Left at its default
  // disposition, that kills the whole process instantly with no log line
  // and no crash report, instead of the EPIPE status that should have just
  // closed that one tunnel (QuictunTunnel::SendComplete() already handles
  // a failed send correctly).
  if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
    return absl::ErrnoToStatus(errno, "signal(SIGPIPE) failed");
  }
  return absl::OkStatus();
}

#if defined(__APPLE__)
// Raises the soft limit on open files to the most the system allows. macOS
// starts processes at 256, far below what a tunnel serving many connections
// uses (one descriptor each), and running out makes accept() and connect()
// fail. Go raises it the same way at startup (syscall/rlimit.go): the low
// default exists for select()'s fixed-size fd_set, and quictun never calls
// select().
absl::Status RaiseOpenFileLimit() {
  rlimit limit;
  if (getrlimit(RLIMIT_NOFILE, &limit) != 0) {
    return absl::ErrnoToStatus(errno, "getrlimit(RLIMIT_NOFILE) failed");
  }
  // The hard limit is often RLIM_INFINITY, which setrlimit() refuses for the
  // soft one; kern.maxfilesperproc is the real ceiling, as Go caps it
  // (syscall/rlimit_darwin.go).
  int max_per_process = 0;
  size_t size = sizeof(max_per_process);
  if (sysctlbyname("kern.maxfilesperproc", &max_per_process, &size, nullptr,
                   0) != 0) {
    return absl::ErrnoToStatus(errno, "sysctl(kern.maxfilesperproc) failed");
  }
  rlim_t target = limit.rlim_max;
  if (max_per_process > 0 && target > static_cast<rlim_t>(max_per_process)) {
    target = static_cast<rlim_t>(max_per_process);
  }
  if (limit.rlim_cur >= target) {
    return absl::OkStatus();
  }
  limit.rlim_cur = target;
  if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
    return absl::ErrnoToStatus(errno, "setrlimit(RLIMIT_NOFILE) failed");
  }
  return absl::OkStatus();
}
#endif  // defined(__APPLE__)

}  // namespace

#if defined(__APPLE__)
absl::Status InitQuictunPlatform() {
  if (absl::Status status = IgnoreSigpipe(); !status.ok()) {
    return status;
  }
  return RaiseOpenFileLimit();
}
#else
absl::Status InitQuictunPlatform() { return IgnoreSigpipe(); }
#endif

}  // namespace quic
