#!/bin/bash
# Builds clang's profile runtime for x86_64 Windows, which a coverage build
# of quictun links: clang_rt.profile.lib, the name clang-cl's objects ask
# lld-link for.
#
# Usage: windows_profile_runtime.sh <output directory>
#
# Built the way setup_toolchain_windows.sh builds libc++, from the LLVM
# source it unpacks, rather than taken from Chromium's clang package: the
# prebuilt one lacks _CRT_STDIO_ISO_WIDE_SPECIFIERS, which libc++'s CMake
# defines for its own objects (libcxx/CMakeLists.txt), and lld-link refuses
# to link objects that disagree on it (/failifmismatch).
set -euo pipefail

OUT=${1:?usage: $0 <output directory>}
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PREFIX="$REPO_ROOT/build/toolchain/out"
CLANG_BIN="$PREFIX/chromium-clang/bin"
WINSDK="$PREFIX/winsdk"
SRC=$(ls -d "$REPO_ROOT"/build/toolchain/.build/llvm-src/llvm-project-* 2>/dev/null | head -1)
if [ ! -x "$CLANG_BIN/clang-cl" ] || [ ! -d "$WINSDK" ] || [ -z "$SRC" ]; then
  echo "Run build/toolchain/setup_toolchain.sh x64 and setup_toolchain_windows.sh x64 first." >&2
  exit 1
fi

TARGET=x86_64-pc-windows-msvc
FLAGS="--target=$TARGET /D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00 /D_CRT_STDIO_ISO_WIDE_SPECIFIERS"
for dir in crt/include sdk/include/ucrt sdk/include/um sdk/include/shared; do
  FLAGS="$FLAGS /imsvc$WINSDK/$dir"
done

BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT
cmake -GNinja -S "$SRC/runtimes" -B "$BUILD_DIR" \
  -DCMAKE_SYSTEM_NAME=Windows \
  -DCMAKE_SYSTEM_PROCESSOR=AMD64 \
  -DCMAKE_C_COMPILER="$CLANG_BIN/clang-cl" \
  -DCMAKE_CXX_COMPILER="$CLANG_BIN/clang-cl" \
  -DCMAKE_LINKER="$CLANG_BIN/lld-link" \
  -DCMAKE_AR="$PREFIX/windows-bin/llvm-lib" \
  -DCMAKE_C_COMPILER_TARGET=$TARGET \
  -DCMAKE_CXX_COMPILER_TARGET=$TARGET \
  -DCMAKE_C_FLAGS="$FLAGS" \
  -DCMAKE_CXX_FLAGS="$FLAGS" \
  -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
  -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_ENABLE_RUNTIMES=compiler-rt \
  -DCOMPILER_RT_BUILD_PROFILE=ON \
  -DCOMPILER_RT_BUILD_BUILTINS=OFF \
  -DCOMPILER_RT_BUILD_SANITIZERS=OFF \
  -DCOMPILER_RT_BUILD_XRAY=OFF \
  -DCOMPILER_RT_BUILD_LIBFUZZER=OFF \
  -DCOMPILER_RT_BUILD_MEMPROF=OFF \
  -DCOMPILER_RT_BUILD_ORC=OFF \
  -DCOMPILER_RT_BUILD_CTX_PROFILE=OFF \
  -DCOMPILER_RT_BUILD_GWP_ASAN=OFF \
  -DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON \
  -DCOMPILER_RT_INCLUDE_TESTS=OFF \
  -DLLVM_INCLUDE_TESTS=OFF
ninja -C "$BUILD_DIR"
mkdir -p "$OUT"
cp "$BUILD_DIR/compiler-rt/lib/windows/clang_rt.profile-x86_64.lib" "$OUT/clang_rt.profile.lib"
echo "$OUT/clang_rt.profile.lib"
