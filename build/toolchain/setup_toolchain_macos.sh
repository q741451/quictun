#!/bin/bash
# The macOS counterpart of setup_toolchain.sh: the same Chromium-pinned clang,
# and libc++/libc++abi built from LLVM source at the same commit, statically
# linked into the binary. What macOS does not allow to be pinned the same way
# is the C library: libSystem is always linked dynamically there, and its
# headers come from Apple's SDK, which has to be Apple's own (its licence only
# allows use on Apple hardware, so this runs on a Mac, never cross from Linux).
# The SDK is pinned by version below and refused if it is anything else.
#
# What is shared with setup_toolchain.sh is read out of it rather than
# repeated: CLANG_PACKAGE_VERSION and LLVM_COMMIT exist in
# exactly one place, so the Linux and macOS binaries cannot drift onto
# different compilers.
#
# Usage: setup_toolchain_macos.sh <arm64|x64>
#
# Runs on an Apple silicon Mac for both: the pinned clang is an arm64 binary
# and targets x86_64 just as well, and the SDK carries both architectures.
# A build for x64 also needs arm64 set up, for the build-time tools Bazel
# runs on the host (the same reason every Linux cross job sets up x64).
#
# Installs under $QUICTUN_TOOLCHAIN_PREFIX, defaulting to this repo's
# build/toolchain/out/, the same directory the Linux script uses, under names
# that cannot collide with it:
#   $PREFIX/chromium-clang-mac/     (Chromium's Mac_arm64 clang package)
#   $PREFIX/libcxx-macos-<arch>/    (static libc++/libc++abi)
# and writes the resolved paths, and the --target of every architecture, to
# build/toolchain/macos/toolchain_paths.bzl.
set -euo pipefail

ARCH=${1:-}

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
PREFIX=${QUICTUN_TOOLCHAIN_PREFIX:-$REPO_ROOT/build/toolchain/out}
BUILD_ROOT=$REPO_ROOT/build/toolchain/.build
FILE_PREFIX_MAP="-ffile-prefix-map=$BUILD_ROOT/="

# --- Pins ---
# Shared with Linux, read from setup_toolchain.sh's own assignments.
eval "$(grep -E '^(CLANG_PACKAGE_VERSION|LLVM_COMMIT)=' \
  "$REPO_ROOT/build/toolchain/setup_toolchain.sh")"
if [ -z "${CLANG_PACKAGE_VERSION:-}" ] || [ -z "${LLVM_COMMIT:-}" ]; then
  echo "Could not read the clang/LLVM pins from setup_toolchain.sh" >&2
  exit 1
fi
# The checksum of the Mac_arm64 build of that CLANG_PACKAGE_VERSION. When
# setup_toolchain.sh moves to a new clang this stops matching and the setup
# fails here, instead of quietly building macOS with an unverified download.
MAC_CLANG_SHA256=a9c5ab02bfdc07a6ad6c6711d884dccab1fdf52e05e71aa9328039cddaff3664
# The SDK that comes with the Xcode the workflow selects (Xcode 16.4).
MACOS_SDK_VERSION=15.5
# Oldest macOS the binaries run on, both architectures. 11.0 is the first
# release on Apple silicon, so for arm64 this excludes nothing.
MACOS_MIN_VERSION=11.0

# This repo's arch name -> Apple's (CMAKE_OSX_ARCHITECTURES, the triple).
# The single source of the triples: BUILD.bazel reads them through the
# generated toolchain_paths.bzl, as the Linux toolchain does.
arch_apple_arch() {
  case "$1" in
    arm64) echo arm64 ;;
    x64)   echo x86_64 ;;
  esac
}
arch_apple_target() {
  echo "$(arch_apple_arch "$1")-apple-macos$MACOS_MIN_VERSION"
}

ALL_ARCHES="arm64 x64"

APPLE_ARCH=$(arch_apple_arch "$ARCH")
if [ -z "$APPLE_ARCH" ]; then
  echo "Usage: $0 <$(echo "$ALL_ARCHES" | tr ' ' '|')>" >&2
  exit 1
fi
APPLE_TARGET=$(arch_apple_target "$ARCH")

if [ "$(uname -s)" != "Darwin" ]; then
  echo "This script runs on macOS only: Apple's SDK may not be used elsewhere." >&2
  exit 1
fi

SDK_PATH=$(xcrun --sdk macosx --show-sdk-path)
SDK_VERSION=$(xcrun --sdk macosx --show-sdk-version)
if [ "$SDK_VERSION" != "$MACOS_SDK_VERSION" ]; then
  echo "macOS SDK is $SDK_VERSION, expected $MACOS_SDK_VERSION ($SDK_PATH)." >&2
  echo "Select the matching Xcode with xcode-select, or update the pin." >&2
  exit 1
fi

CLANG_DIR="$PREFIX/chromium-clang-mac"
CLANG="$CLANG_DIR/bin/clang"
LIBCXX_DIR="$PREFIX/libcxx-macos-$ARCH"
mkdir -p "$PREFIX" "$BUILD_ROOT"

# As abi_stamp_check in setup_toolchain.sh: each stage below rebuilds only
# if its output is missing, so a libc++ built for an older triple (say, a
# different MACOS_MIN_VERSION) would otherwise be reused. Discard it when
# the triple changes. CI never needs this, since its cache key hashes this
# script; it is for incremental local builds.
STAMP="$PREFIX/.abi-stamp-macos-$ARCH"
if [ -e "$STAMP" ] && [ "$(cat "$STAMP")" != "$APPLE_TARGET" ]; then
  echo "== Target changed for $ARCH ($(cat "$STAMP") -> $APPLE_TARGET): discarding its libc++ =="
  rm -rf "$LIBCXX_DIR" "$BUILD_ROOT/libcxx-macos-$ARCH"
fi
printf '%s' "$APPLE_TARGET" > "$STAMP"

# --- 1. Chromium's pinned clang, Mac_arm64 build of the same version ---
# Unlike the Linux package, this one already carries compiler-rt for macOS
# (lib/clang/*/lib/darwin/libclang_rt.osx.a), so nothing here builds it.
if [ ! -e "$CLANG" ]; then
  echo "== Downloading Chromium's pinned clang for Mac ($CLANG_PACKAGE_VERSION) =="
  TARBALL="$BUILD_ROOT/clang-mac-$CLANG_PACKAGE_VERSION.tar.xz"
  curl -fsSL --retry 3 -o "$TARBALL" \
    "https://commondatastorage.googleapis.com/chromium-browser-clang/Mac_arm64/clang-${CLANG_PACKAGE_VERSION}.tar.xz"
  echo "$MAC_CLANG_SHA256  $TARBALL" | shasum -a 256 -c -
  rm -rf "$CLANG_DIR"
  mkdir -p "$CLANG_DIR"
  tar -xJf "$TARBALL" -C "$CLANG_DIR"
  rm -f "$TARBALL"
fi
CLANG_RESOURCE_DIR=$("$CLANG" -print-resource-dir)

# --- 2. LLVM source, the same commit setup_toolchain.sh builds from ---
SRC_ROOT=$BUILD_ROOT/llvm-src
SRC="$SRC_ROOT/llvm-project-$LLVM_COMMIT"
if [ ! -d "$SRC" ]; then
  mkdir -p "$SRC_ROOT"
  TARBALL="$SRC_ROOT/llvm-$LLVM_COMMIT.tar.gz"
  curl -fsSL --retry 3 -o "$TARBALL" \
    "https://github.com/llvm/llvm-project/archive/${LLVM_COMMIT}.tar.gz"
  tar -xzf "$TARBALL" -C "$SRC_ROOT" \
    "llvm-project-$LLVM_COMMIT/libcxx" \
    "llvm-project-$LLVM_COMMIT/libcxxabi" \
    "llvm-project-$LLVM_COMMIT/libunwind" \
    "llvm-project-$LLVM_COMMIT/runtimes" \
    "llvm-project-$LLVM_COMMIT/cmake" \
    "llvm-project-$LLVM_COMMIT/third-party" \
    "llvm-project-$LLVM_COMMIT/llvm/cmake" \
    "llvm-project-$LLVM_COMMIT/llvm/utils/lit" \
    "llvm-project-$LLVM_COMMIT/llvm/include/llvm-c" \
    "llvm-project-$LLVM_COMMIT/llvm/include/llvm/Config" \
    "llvm-project-$LLVM_COMMIT/llvm/include/llvm/Support" \
    "llvm-project-$LLVM_COMMIT/llvm/include/llvm/ADT" \
    "llvm-project-$LLVM_COMMIT/llvm/include/llvm/Demangle" \
    "llvm-project-$LLVM_COMMIT/llvm/include/llvm/TargetParser" \
    "llvm-project-$LLVM_COMMIT/libc"
  rm -f "$TARBALL"
fi

# --- 3. libc++/libc++abi, static ---
# The unwinder stays the system one: on macOS it is part of libSystem, which
# is linked anyway, and quictun is built -fno-exceptions. Same
# LIBCXXABI_NON_DEMANGLING_TERMINATE as Linux, for the same reason.
if [ ! -e "$LIBCXX_DIR/lib/libc++.a" ]; then
  echo "== Building libc++ for $APPLE_TARGET =="
  BUILD_DIR="$BUILD_ROOT/libcxx-macos-$ARCH"
  rm -rf "$BUILD_DIR"
  mkdir -p "$BUILD_DIR"

  FLAGS="--target=$APPLE_TARGET -isysroot $SDK_PATH $FILE_PREFIX_MAP"
  cmake -GNinja -S "$SRC/runtimes" -B "$BUILD_DIR" \
    -DCMAKE_C_COMPILER="$CLANG" \
    -DCMAKE_CXX_COMPILER="$CLANG_DIR/bin/clang++" \
    -DCMAKE_AR="$CLANG_DIR/bin/llvm-ar" \
    -DCMAKE_RANLIB="$CLANG_DIR/bin/llvm-ar" \
    -DCMAKE_OSX_SYSROOT="$SDK_PATH" \
    -DCMAKE_OSX_ARCHITECTURES="$APPLE_ARCH" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET="$MACOS_MIN_VERSION" \
    -DCMAKE_C_FLAGS="$FLAGS" \
    -DCMAKE_CXX_FLAGS="$FLAGS" \
    -DCMAKE_ASM_FLAGS="$FLAGS" \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi" \
    -DLIBCXXABI_USE_LLVM_UNWINDER=OFF \
    -DLIBCXX_CXX_ABI=libcxxabi \
    -DLIBCXXABI_NON_DEMANGLING_TERMINATE=ON \
    -DLIBCXX_ENABLE_SHARED=OFF \
    -DLIBCXX_ENABLE_STATIC=ON \
    -DLIBCXXABI_ENABLE_SHARED=OFF \
    -DLIBCXXABI_ENABLE_STATIC=ON \
    -DLIBCXX_INCLUDE_TESTS=OFF \
    -DLIBCXXABI_INCLUDE_TESTS=OFF \
    -DLIBCXX_INCLUDE_BENCHMARKS=OFF \
    -DLLVM_INCLUDE_TESTS=OFF

  ninja -C "$BUILD_DIR" cxx cxxabi

  mkdir -p "$LIBCXX_DIR"
  cp -r "$BUILD_DIR/lib" "$BUILD_DIR/include" "$LIBCXX_DIR/"
fi

# --- 4. Hand the resolved paths to Bazel ---
cat > "$REPO_ROOT/build/toolchain/macos/toolchain_paths.bzl" <<EOF
"""Generated by build/toolchain/setup_toolchain_macos.sh -- do not edit or commit."""

TOOLCHAIN_PREFIX = "$PREFIX"
CLANG_RESOURCE_DIR = "$CLANG_RESOURCE_DIR"
SDK_PATH = "$SDK_PATH"

# Every architecture's clang --target, not just the one just set up.
MACOS_TARGETS = {
$(for a in $ALL_ARCHES; do printf '    "%s": "%s",\n' "$a" "$(arch_apple_target "$a")"; done)
}
EOF

echo "== Done: macOS $ARCH toolchain ready =="
echo "  clang:   $CLANG"
echo "  sdk:     $SDK_PATH ($SDK_VERSION)"
echo "  libc++:  $LIBCXX_DIR"
