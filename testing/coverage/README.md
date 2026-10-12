# Which platform branches testing/smoke actually runs

A build of quictun with clang's source-based coverage of `quiche/`, run
through `testing/smoke`, then a per-line report of the files whose code
differs by platform (`*_posix.inc` / `*_win.inc`, the event loop, the
sockets, quictun's own drivers). It shows which `#if` branches the smoke
cases reach on macOS and Windows, where Linux's behaviour is the reference
and the others are only as tested as these cases make them. That is how the
Windows dual-stack and non-ASCII `--key` bugs were found.

| Script | Does |
| --- | --- |
| `windows_profile_runtime.sh <dir>` | Builds clang's profile runtime for x86_64 Windows into `<dir>/clang_rt.profile.lib`, from the LLVM source `build/toolchain/setup_toolchain_windows.sh` unpacks and the way it builds libc++. Chromium's prebuilt one cannot be linked with libc++ (`/failifmismatch` on `_CRT_STDIO_ISO_WIDE_SPECIFIERS`). |
| `report.sh <profiles> <out> <binary>...` | Merges `<profiles>/*.profraw` and writes `summary.txt` (per file) and `show.txt` (per line) to `<out>`. Uses `llvm-profdata`/`llvm-cov` from Chromium's `llvm-code-coverage` package of the clang `setup_toolchain.sh` pins, checked against a hash; Linux x86_64 and macOS arm64 hosts. |

In CI it is off by default. To run it, start the *Build* workflow by hand
(*Actions* tab, *Build*, *Run workflow*) with **coverage** ticked. On macOS
15 (arm64) one job builds, runs the smoke test and reports; for Windows the
build and the report run on Linux and the smoke test on Windows Server
2022. The reports are the run's `coverage-macos-arm64` and
`coverage-windows-x86_64` artifacts. A failing smoke case still produces a
report, and the job still fails.

The build is the normal one plus `-fprofile-instr-generate
-fcoverage-mapping -DQUICTUN_COVERAGE_BUILD` on `quiche/`, so everything
under `quiche/` is measured and nothing else. The profile is written when a
process exits, or, in such a build, when it gets SIGTERM or (Windows)
CTRL_BREAK_EVENT, which is how `smoke_test.py` stops it; a process that has
to be killed leaves none.

Locally, on macOS, against a build of your own:

```
bazel build -c opt --platforms=//build/toolchain/macos:macos_arm64 \
  '--per_file_copt=quiche/.*@-fprofile-instr-generate,-fcoverage-mapping,-DQUICTUN_COVERAGE_BUILD' \
  --linkopt=-fprofile-instr-generate //quiche:quictun_client //quiche:quictun_server
mkdir -p /tmp/qt /tmp/qt-prof && cp bazel-bin/quiche/quictun_client /tmp/qt/quictun_client-macos-arm64 \
  && cp bazel-bin/quiche/quictun_server /tmp/qt/quictun_server-macos-arm64
LLVM_PROFILE_FILE=/tmp/qt-prof/%p.profraw python3 testing/smoke/smoke_test.py /tmp/qt
testing/coverage/report.sh /tmp/qt-prof /tmp/qt-report /tmp/qt/*
```

Expect `llvm-cov` to warn that some functions "have mismatched data":
inline functions that `-c opt` folded away, leaving a mapping with no
counters behind. They do not affect the report.

Linux is not covered here: its binaries link musl, and the profile runtime
in Chromium's clang package is built for glibc only.
