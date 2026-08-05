#!/bin/bash
# Sets up a from-scratch, pinned, Chromium-style toolchain for one target
# architecture: Chromium's own pinned clang/lld/llvm-* binaries, a
# from-source-built libc++/libc++abi/libunwind (built by that same clang,
# from LLVM source at the exact same commit), and glibc headers/libs
# pinned to a fixed Ubuntu archive snapshot -- see build/toolchain/BUILD.bazel
# for why each of those three pieces is pinned the way it is, and why this
# is not simply Chromium's own sysroot (it has no static libs) or a plain
# `apt install gcc-<triple>-cross` (that drifts across Ubuntu releases,
# which is what broke mipsel the first time -- see git history).
#
# Usage: setup_toolchain.sh <x64|arm64|armv7|mipsel>
#
# Produces:
#   /opt/chromium-clang        (shared across all archs)
#   /opt/libcxx-<arch>/lib, /opt/libcxx-<arch>/include/c++/v1
#   glibc headers/libs installed to their normal apt paths (/usr/..., or
#   /usr/<triple>/... for the cross packages)
set -euo pipefail

ARCH=$1

# --- Pins ---
# Chromium's actual current clang, from tools/clang/scripts/update.py
# (CLANG_REVISION/CLANG_SUB_REVISION) as of 2026-06-16.
CLANG_PACKAGE_VERSION=llvmorg-23-init-19482-g53d18800-2
LLVM_COMMIT=53d18800eda3b7407e53366f27ca78e922c6e0db
# Ubuntu archive snapshot, pinned to the day after the clang commit above,
# so glibc and the compiler are from roughly the same point in time.
SNAPSHOT_TS=20260617T000000Z

case "$ARCH" in
  x64)
    TRIPLE=x86_64-unknown-linux-gnu
    GLIBC_PKGS="libc6-dev libc6 linux-libc-dev libcrypt-dev"
    ;;
  arm64)
    TRIPLE=aarch64-unknown-linux-gnu
    GLIBC_PKGS="libc6-dev-arm64-cross libc6-arm64-cross linux-libc-dev-arm64-cross"
    ;;
  armv7)
    TRIPLE=armv7-unknown-linux-gnueabihf
    GLIBC_PKGS="libc6-dev-armhf-cross libc6-armhf-cross linux-libc-dev-armhf-cross"
    ;;
  mipsel)
    TRIPLE=mipsel-unknown-linux-gnu
    # Chromium's clang package ships no compiler-rt/crtbegin for MIPS at
    # all (Chromium/V8 dropped MIPS support in 2019), so this is the one
    # target that still needs a real GCC's runtime pieces (crtbeginS.o,
    # libgcc.a, libatomic.a) -- pinned to the same snapshot as everything
    # else, rather than left as a live `apt install` version.
    GLIBC_PKGS="libc6-dev-mipsel-cross libc6-mipsel-cross linux-libc-dev-mipsel-cross libgcc-10-dev-mipsel-cross"
    ;;
  *)
    echo "Usage: $0 <x64|arm64|armv7|mipsel>" >&2
    exit 1
    ;;
esac

# --- 1. Chromium's pinned clang/lld/llvm-ar/etc ---
if [ ! -e /opt/chromium-clang/bin/clang ]; then
  echo "== Downloading Chromium's pinned clang ($CLANG_PACKAGE_VERSION) =="
  sudo mkdir -p /opt/chromium-clang
  curl -fsSL "https://commondatastorage.googleapis.com/chromium-browser-clang/Linux_x64/clang-${CLANG_PACKAGE_VERSION}.tar.xz" \
    | sudo tar -xJ -C /opt/chromium-clang
  # llvm-ar acts as ranlib/nm/etc when invoked under those names; the
  # package only ships the canonical binary.
  sudo ln -sf llvm-ar /opt/chromium-clang/bin/llvm-ranlib
fi

# --- 2. glibc headers/libs, pinned to a fixed Ubuntu snapshot ---
echo "== Installing $GLIBC_PKGS from snapshot $SNAPSHOT_TS =="
sudo apt-get install -y -qq $GLIBC_PKGS --update --snapshot "$SNAPSHOT_TS"

# --- 3. libc++/libc++abi/libunwind, built from LLVM source at the same
# commit as the clang binary, targeting $TRIPLE ---
LIBCXX_OUT="/opt/libcxx-$ARCH"
if [ ! -e "$LIBCXX_OUT/lib/libc++.a" ]; then
  echo "== Building libc++ for $TRIPLE =="
  SRC_ROOT=/tmp/llvm-src
  SRC="$SRC_ROOT/llvm-project-$LLVM_COMMIT"
  if [ ! -d "$SRC" ]; then
    mkdir -p "$SRC_ROOT"
    curl -fsSL "https://github.com/llvm/llvm-project/archive/${LLVM_COMMIT}.tar.gz" \
      | tar -xz -C "$SRC_ROOT" \
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
  fi

  BUILD_DIR="/tmp/libcxx-build-$ARCH"
  rm -rf "$BUILD_DIR"
  mkdir -p "$BUILD_DIR"

  EXTRA_LINKER_FLAGS=""
  if [ "$ARCH" = "mipsel" ]; then
    # Old GCC10-generation crt objects (mipsel has no Chromium compiler-rt,
    # see above) lack a modern .note.GNU-stack marking; ld.lld's stricter
    # default rejects them without this.
    EXTRA_LINKER_FLAGS="-Wl,-z,execstack"
  fi

  cmake -GNinja -S "$SRC/runtimes" -B "$BUILD_DIR" \
    -DCMAKE_C_COMPILER=/opt/chromium-clang/bin/clang \
    -DCMAKE_CXX_COMPILER=/opt/chromium-clang/bin/clang++ \
    -DCMAKE_ASM_COMPILER_TARGET="$TRIPLE" \
    -DCMAKE_AR=/opt/chromium-clang/bin/llvm-ar \
    -DCMAKE_RANLIB=/opt/chromium-clang/bin/llvm-ranlib \
    -DCMAKE_C_COMPILER_TARGET="$TRIPLE" \
    -DCMAKE_CXX_COMPILER_TARGET="$TRIPLE" \
    -DCMAKE_C_FLAGS="-fuse-ld=lld -I$SRC/libc" \
    -DCMAKE_CXX_FLAGS="-fuse-ld=lld -I$SRC/libc" \
    -DCMAKE_EXE_LINKER_FLAGS="$EXTRA_LINKER_FLAGS" \
    -DCMAKE_SHARED_LINKER_FLAGS="$EXTRA_LINKER_FLAGS" \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi;libunwind" \
    -DLIBCXXABI_USE_LLVM_UNWINDER=ON \
    -DLIBCXX_CXX_ABI=libcxxabi \
    -DLIBCXX_ENABLE_SHARED=OFF \
    -DLIBCXX_ENABLE_STATIC=ON \
    -DLIBCXXABI_ENABLE_SHARED=OFF \
    -DLIBCXXABI_ENABLE_STATIC=ON \
    -DLIBUNWIND_ENABLE_SHARED=OFF \
    -DLIBUNWIND_ENABLE_STATIC=ON \
    -DLIBCXX_INCLUDE_TESTS=OFF \
    -DLIBCXXABI_INCLUDE_TESTS=OFF \
    -DLIBUNWIND_INCLUDE_TESTS=OFF \
    -DLIBCXX_INCLUDE_BENCHMARKS=OFF \
    -DLLVM_INCLUDE_TESTS=OFF

  ninja -C "$BUILD_DIR" -j"$(nproc)" cxx cxxabi unwind

  sudo mkdir -p "$LIBCXX_OUT"
  sudo cp -r "$BUILD_DIR/lib" "$BUILD_DIR/include" "$LIBCXX_OUT/"
fi

echo "== Done: $ARCH toolchain ready =="
echo "  clang:  /opt/chromium-clang/bin/clang"
echo "  libc++: $LIBCXX_OUT"
