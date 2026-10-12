// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_platform.h"

#if defined(_WIN32)
#include <winsock2.h>
#include <windows.h>
#include <timeapi.h>

#include "absl/strings/str_cat.h"
#else
#include <cerrno>
#include <csignal>
#endif
#if defined(__APPLE__)
#include <sys/resource.h>
#include <sys/sysctl.h>
#endif

#include "absl/status/status.h"

namespace quic {

namespace {

#if defined(_WIN32)
// Windows 10 2004 (build 19041), the first whose WSAPoll() reports a
// non-blocking connect() that failed; quictun_server's connect to --target
// depends on that. setup_toolchain_windows.sh's WINDOWS_MIN_VERSION says the
// same for the image.
constexpr unsigned long kMinWindowsBuild = 19041;

absl::Status CheckWindowsVersion() {
  // RtlGetVersion rather than GetVersionEx, which reports an older Windows
  // than the real one to a program without a compatibility manifest --
  // msquic determines the version the same way (platform_winuser.c).
  using RtlGetVersionFn = LONG(WINAPI*)(RTL_OSVERSIONINFOW*);
  RTL_OSVERSIONINFOW version = {};
  version.dwOSVersionInfoSize = sizeof(version);
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  auto rtl_get_version =
      ntdll == nullptr ? nullptr
                       : reinterpret_cast<RtlGetVersionFn>(
                             GetProcAddress(ntdll, "RtlGetVersion"));
  if (rtl_get_version == nullptr || rtl_get_version(&version) != 0) {
    return absl::InternalError("Cannot determine the Windows version");
  }
  if (version.dwMajorVersion < 10 ||
      (version.dwMajorVersion == 10 &&
       version.dwBuildNumber < kMinWindowsBuild)) {
    return absl::FailedPreconditionError(absl::StrCat(
        "Windows 10 2004 (build ", kMinWindowsBuild,
        ") or later is required; this is ", version.dwMajorVersion, ".",
        version.dwMinorVersion, " build ", version.dwBuildNumber));
  }
  return absl::OkStatus();
}
#else
absl::Status IgnoreSigpipe() {
  // quic::socket_api::Send() (quic/core/io/socket.cc) is a bare ::send()
  // with no MSG_NOSIGNAL, so writing to a tunneled TCP socket -- the
  // client's --local one, the server's --target one -- after its peer
  // already reset the connection, routine whenever a download being
  // tunneled gets cancelled, delivers SIGPIPE. Left at its default
  // disposition, that kills the whole process instantly with no log line
  // and no crash report, instead of the EPIPE status that should have just
  // closed that one tunnel (QuictunTunnel::SendComplete() already handles
  // a failed send correctly). Windows has no SIGPIPE: such a send fails
  // with WSAECONNRESET.
  if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
    return absl::ErrnoToStatus(errno, "signal(SIGPIPE) failed");
  }
  return absl::OkStatus();
}
#endif

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

#if defined(_WIN32)
absl::Status InitQuictunPlatform() {
  // Winsock must be started before any socket call; QUICHE leaves that to
  // the program, as msquic does in its own datapath setup.
  WSADATA wsa_data;
  if (int error = WSAStartup(MAKEWORD(2, 2), &wsa_data); error != 0) {
    return absl::InternalError(absl::StrCat("WSAStartup() failed: ", error));
  }
  if (absl::Status status = CheckWindowsVersion(); !status.ok()) {
    return status;
  }
  // The event loop sleeps in WSAPoll(), whose timeout is rounded to the
  // system timer's period, 15.6ms by default: pacing deadlines a few ms
  // out would then be missed by up to that much, and packets go out in
  // bursts. Raised to the finest period the timer supports, as msquic does
  // (timeGetDevCaps + timeBeginPeriod, platform_winuser.c); since Windows
  // 10 2004 the setting only affects this process.
  TIMECAPS caps;
  if (MMRESULT r = timeGetDevCaps(&caps, sizeof(caps)); r != TIMERR_NOERROR) {
    return absl::InternalError(absl::StrCat("timeGetDevCaps() failed: ", r));
  }
  if (MMRESULT r = timeBeginPeriod(caps.wPeriodMin); r != TIMERR_NOERROR) {
    return absl::InternalError(absl::StrCat("timeBeginPeriod() failed: ", r));
  }
  return absl::OkStatus();
}
#elif defined(__APPLE__)
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
