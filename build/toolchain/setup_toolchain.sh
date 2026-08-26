#!/bin/bash
# Sets up a from-scratch, pinned toolchain for one target architecture:
# Chromium's own pinned clang/lld/llvm-* binaries, a from-source-built musl
# libc, and a from-source-built libc++/libc++abi/libunwind (built by that
# same clang, from LLVM source at the exact same commit, against that musl).
#
# Nothing here comes from the build host's distro. No apt, no sudo, no
# /usr/include, no system libc. Every input is either downloaded at a pinned
# version and checksum-verified, or built from source by the pinned clang.
# That is the whole point: a plain `apt install gcc-<triple>-cross` drifts
# across Ubuntu releases, which is what broke mipsel the first time (see git
# history), and a build that reads /usr/include silently inherits whatever
# the runner image happens to ship this month.
#
# musl rather than glibc, for three reasons:
#   1. Size: static glibc contributes ~770KB to each binary that musl doesn't.
#   2. Static-linking sharp edges: armhf/mipsel cross-glibc ships no rcrt1.o,
#      so those two arches had to fall back from -static-pie to plain -static,
#      and glibc 2.34+'s x86_64 static libc.a forced -static-pie there for an
#      unrelated reason. musl ships rcrt1.o everywhere -- every arch links the
#      same way.
#   3. Self-containment: glibc's headers/libs realistically have to come from
#      the distro, which is exactly what this file is trying to avoid. musl
#      builds from a 1MB tarball in about a minute.
#
# quictun needs no kernel UAPI headers (<linux/*>), which musl deliberately
# does not ship: the handful of constants involved are defined inline behind
# __has_include guards at their use sites. See quictun_connection_factory.cc,
# flow_label.h and quic_udp_socket_posix.inc.
#
# Usage: setup_toolchain.sh <x64|arm64|armv7|mipsel>
#
# Installs under $QUICTUN_TOOLCHAIN_PREFIX, defaulting to this repo's
# build/toolchain/out/ -- a working directory, not a system path, so this
# script never needs root and never modifies the host:
#   $PREFIX/chromium-clang/     (shared across all archs)
#   $PREFIX/musl-<arch>/        (sysroot: musl headers + libs)
#   $PREFIX/libcxx-<arch>/      (libc++/libc++abi/libunwind against that musl)
# and writes the resolved paths to build/toolchain/toolchain_paths.bzl for
# BUILD.bazel to read, since they are no longer a fixed location.
set -euo pipefail

ARCH=${1:-}

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
PREFIX=${QUICTUN_TOOLCHAIN_PREFIX:-$REPO_ROOT/build/toolchain/out}

# --- Pins ---
# Chromium's actual current clang, from tools/clang/scripts/update.py
# (CLANG_REVISION/CLANG_SUB_REVISION) as of 2026-06-16.
CLANG_PACKAGE_VERSION=llvmorg-23-init-19482-g53d18800-2
LLVM_COMMIT=53d18800eda3b7407e53366f27ca78e922c6e0db
# musl release, checksum from https://musl.libc.org/releases/ (verified
# against the downloaded tarball, not transcribed from memory).
MUSL_VERSION=1.2.5
MUSL_SHA256=a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4

# MUSL_TARGET drives musl's own build, compiler-rt's, and clang's --target for
# everything compiled against them. KERNEL_ARCH selects which vendored asm/
# tree to install (see build/toolchain/uapi/).
case "$ARCH" in
  x64)
    MUSL_TARGET=x86_64-linux-musl
    KERNEL_ARCH=x86
    ;;
  arm64)
    MUSL_TARGET=aarch64-linux-musl
    KERNEL_ARCH=arm64
    ;;
  armv7)
    # armv7, not armv7l: the trailing l is uname's spelling, not LLVM's, and
    # compiler-rt's ARM32 arch list has no entry for it, so a builtins build
    # configures with nothing to do and silently produces no library. Both
    # spellings normalise to the same effective triple
    # (armv7-unknown-linux-musleabihf), so this changes nothing else. Plain
    # "arm-" is not the fix: clang normalises that down to armv6kz.
    MUSL_TARGET=armv7-linux-musleabihf
    KERNEL_ARCH=arm
    ;;
  mipsel)
    MUSL_TARGET=mipsel-linux-musl
    KERNEL_ARCH=mips
    ;;
  *)
    echo "Usage: $0 <x64|arm64|armv7|mipsel>" >&2
    exit 1
    ;;
esac

# musl deliberately ships no kernel UAPI headers (<linux/*>), and pulling a
# whole kernel-headers package in for them would be both enormous and exactly
# the kind of external dependency this file exists to avoid. quictun's own
# code needs none -- it defines the handful of constants it uses inline behind
# __has_include guards. Third-party dependencies aren't ours to patch, though,
# so the few headers they include are shimmed here, each providing only what
# its consumer actually uses:
#
#   linux/futex.h    libc++ atomic.cpp and abseil's futex waiter
#   linux/unistd.h   abseil direct_mmap.h, for __NR_{mmap,mmap2,munmap}
#   linux/random.h   BoringSSL urandom.cc, for GRND_NONBLOCK
#
# <asm/*> is deliberately NOT hand-written: it is the one part of the UAPI
# that varies per architecture, so hand-maintaining it means rediscovering a
# missing header (and hand-transcribing its values) every time a target is
# added -- and a wrong bit there is not a missing optimisation but a SIGILL,
# on hardware that can't be tested from a dev machine. Those come verbatim
# from build/toolchain/uapi/, generated by the kernel's own
# `make headers_install`; see that directory's README.
#
# All of this is UAPI: fixed forever by definition, so there's no version to
# track. Anything that needs more than these will fail loudly at compile time
# with a "file not found", not silently.
install_uapi_shims() {
  local sysroot=$1
  mkdir -p "$sysroot/include/linux"

  cat > "$sysroot/include/linux/futex.h" <<'FUTEX_EOF'
/* Generated by build/toolchain/setup_toolchain.sh -- see install_uapi_shims.
   Full FUTEX_* operation set, values straight from the kernel's own futex.h.

   Completeness matters beyond the one or two constants any single consumer
   dereferences: abseil gates its entire futex-based synchronization backend on
   `#if defined(__linux__) && defined(FUTEX_CLOCK_REALTIME)` and silently falls
   back to pthread/semaphore waiters when that is missing. A shim carrying only
   FUTEX_WAIT/FUTEX_WAKE compiles and passes tests while quietly downgrading
   every mutex in the binary. */
#ifndef _QUICTUN_UAPI_SHIM_LINUX_FUTEX_H
#define _QUICTUN_UAPI_SHIM_LINUX_FUTEX_H

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_FD 2
#define FUTEX_REQUEUE 3
#define FUTEX_CMP_REQUEUE 4
#define FUTEX_WAKE_OP 5
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_TRYLOCK_PI 8
#define FUTEX_WAIT_BITSET 9
#define FUTEX_WAKE_BITSET 10

#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_CLOCK_REALTIME 256

#define FUTEX_WAIT_PRIVATE (FUTEX_WAIT | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAKE_PRIVATE (FUTEX_WAKE | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAIT_BITSET_PRIVATE (FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAKE_BITSET_PRIVATE (FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG)

#define FUTEX_BITSET_MATCH_ANY 0xffffffff

#endif
FUTEX_EOF

  cat > "$sysroot/include/linux/unistd.h" <<'UNISTD_EOF'
/* Generated by build/toolchain/setup_toolchain.sh -- see install_uapi_shims.
   The kernel header's job here is to define __NR_*; musl already does that in
   <bits/syscall.h>, reached through <sys/syscall.h>, so just forward to it. */
#ifndef _QUICTUN_UAPI_SHIM_LINUX_UNISTD_H
#define _QUICTUN_UAPI_SHIM_LINUX_UNISTD_H

#include <sys/syscall.h>

#endif
UNISTD_EOF


  cat > "$sysroot/include/linux/random.h" <<'RANDOM_EOF'
/* Generated by build/toolchain/setup_toolchain.sh -- see install_uapi_shims.
   musl declares the same GRND_* flags, with the same values, in
   <sys/random.h>; forward rather than restate them. */
#ifndef _QUICTUN_UAPI_SHIM_LINUX_RANDOM_H
#define _QUICTUN_UAPI_SHIM_LINUX_RANDOM_H

#include <sys/random.h>

#endif
RANDOM_EOF
}

# compiler-rt (builtins + crtbegin/crtend), built from the same LLVM source as
# libc++ and targeting musl directly.
#
# Chromium's clang package ships prebuilt compiler-rt only under *-linux-gnu
# triples, and none at all for MIPS -- Chromium/V8 dropped MIPS in 2019. The
# glibc toolchain worked around the MIPS gap by pulling libgcc, libgcc_eh and
# libatomic out of an apt gcc-mipsel-cross package (and turning on an
# executable stack to satisfy its crt objects), which is exactly the distro
# dependency this file exists to remove. Building it here instead makes every
# architecture identical, needs no triple-aliasing to make clang's lookup
# resolve, and drops the executable-stack concession.
build_compiler_rt() {
  local out="$CLANG_RESOURCE_DIR/lib/$RT_MUSL_TRIPLE"
  [ -e "$out/libclang_rt.builtins.a" ] && return 0

  echo "== Building compiler-rt builtins for $MUSL_TARGET =="
  local build_dir="/tmp/compiler-rt-build-$ARCH"
  # cmake -B would create this itself, but the log redirections below are
  # opened by the shell before cmake ever runs.
  rm -rf "$build_dir"
  mkdir -p "$build_dir"
  cmake -GNinja -S "$SRC/compiler-rt/lib/builtins" -B "$build_dir" \
    -DCMAKE_C_COMPILER="$CLANG" \
    -DCMAKE_CXX_COMPILER="$CLANG_DIR/bin/clang++" \
    -DCMAKE_ASM_COMPILER="$CLANG" \
    -DCMAKE_AR="$CLANG_DIR/bin/llvm-ar" \
    -DCMAKE_RANLIB="$CLANG_DIR/bin/llvm-ranlib" \
    -DCMAKE_C_COMPILER_TARGET="$MUSL_TARGET" \
    -DCMAKE_CXX_COMPILER_TARGET="$MUSL_TARGET" \
    -DCMAKE_ASM_COMPILER_TARGET="$MUSL_TARGET" \
    -DCMAKE_SYSROOT="$MUSL_DIR" \
    -DCMAKE_C_FLAGS="--target=$MUSL_TARGET --sysroot=$MUSL_DIR" \
    -DCMAKE_CXX_FLAGS="--target=$MUSL_TARGET --sysroot=$MUSL_DIR" \
    -DCMAKE_ASM_FLAGS="--target=$MUSL_TARGET --sysroot=$MUSL_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCOMPILER_RT_STANDALONE_BUILD=ON \
    -DCOMPILER_RT_BUILD_CRT=ON \
    -DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON \
    -DLLVM_CMAKE_DIR="$SRC/llvm/cmake/modules" > "$build_dir/cmake.log" 2>&1 \
    || { echo "compiler-rt configure failed:" >&2; tail -40 "$build_dir/cmake.log" >&2; exit 1; }
  ninja -C "$build_dir" -j"$(nproc)" > "$build_dir/build.log" 2>&1 \
    || { echo "compiler-rt build failed:" >&2; tail -40 "$build_dir/build.log" >&2; exit 1; }

  # The builtins-only build emits the old per-arch-suffix layout
  # (lib/linux/libclang_rt.builtins-<arch>.a) while clang looks for the
  # per-triple one (lib/<triple>/libclang_rt.builtins.a), so rename on install
  # rather than leaving clang unable to find what was just built.
  # A builtins build whose target arch compiler-rt doesn't recognise
  # configures happily, reports "no work to do", and produces nothing -- so
  # check for the artifact rather than trusting the exit codes above.
  local built
  built=$(find "$build_dir" -name 'libclang_rt.builtins*.a' | head -1)
  if [ -z "$built" ]; then
    echo "compiler-rt built no library for $MUSL_TARGET." >&2
    echo "Its arch is most likely not in compiler-rt's supported list --" >&2
    echo "check the first triple component against ALL_BUILTIN_SUPPORTED_ARCH" >&2
    echo "in compiler-rt/cmake/builtin-config-ix.cmake." >&2
    exit 1
  fi

  mkdir -p "$out"
  cp "$built" "$out/libclang_rt.builtins.a"
  cp "$build_dir"/lib/linux/clang_rt.crtbegin-*.o "$out/clang_rt.crtbegin.o"
  cp "$build_dir"/lib/linux/clang_rt.crtend-*.o "$out/clang_rt.crtend.o"
}

CLANG_DIR="$PREFIX/chromium-clang"
MUSL_DIR="$PREFIX/musl-$ARCH"
LIBCXX_DIR="$PREFIX/libcxx-$ARCH"
CLANG="$CLANG_DIR/bin/clang"

mkdir -p "$PREFIX"

# --- 1. Chromium's pinned clang/lld/llvm-* ---
if [ ! -e "$CLANG" ]; then
  echo "== Downloading Chromium's pinned clang ($CLANG_PACKAGE_VERSION) =="
  mkdir -p "$CLANG_DIR"
  curl -fsSL "https://commondatastorage.googleapis.com/chromium-browser-clang/Linux_x64/clang-${CLANG_PACKAGE_VERSION}.tar.xz" \
    | tar -xJ -C "$CLANG_DIR"
  # llvm-ar acts as ranlib/nm/etc when invoked under those names; the
  # package only ships the canonical binary.
  ln -sf llvm-ar "$CLANG_DIR/bin/llvm-ranlib"
fi

# Clang's resource directory is versioned by major release; derive it rather
# than hardcoding, so bumping CLANG_PACKAGE_VERSION doesn't silently break
# the alias below.
CLANG_RESOURCE_DIR=$("$CLANG" -print-resource-dir)

# The directory clang will actually search for compiler-rt. Taken from clang
# itself rather than derived: it is *not* -print-effective-triple, which
# normalises armv7l down to armv7 while the runtime lookup keeps the l.
RT_MUSL_TRIPLE=$(basename "$(dirname "$("$CLANG" --target="$MUSL_TARGET" \
  --rtlib=compiler-rt -print-libgcc-file-name)")")

# --- 2. musl, built from source by that same clang ---
if [ ! -e "$MUSL_DIR/lib/libc.a" ]; then
  echo "== Building musl $MUSL_VERSION for $MUSL_TARGET =="
  SRC_ROOT=/tmp/musl-src
  mkdir -p "$SRC_ROOT"
  TARBALL="$SRC_ROOT/musl-$MUSL_VERSION.tar.gz"
  # Deliberately not musl.libc.org: upstream's own host has never once been
  # reachable from here (repeated SSL_ERROR_SYSCALL, from both a dev machine
  # and CI). Mirrors are safe to rely on because the SHA256 below -- not the
  # hostname -- is what's trusted; a tampered mirror fails the checksum.
  # Both verified reachable with a matching checksum; gentoo/openbsd
  # distfiles were tried too and are not reachable from here at all.
  MUSL_URLS=(
    "https://sources.openwrt.org/musl-$MUSL_VERSION.tar.gz"
    "https://sources.buildroot.net/musl/musl-$MUSL_VERSION.tar.gz"
  )
  if [ ! -e "$TARBALL" ]; then
    for url in "${MUSL_URLS[@]}"; do
      echo "  trying $url"
      if curl -fsSL --retry 3 --connect-timeout 20 "$url" -o "$TARBALL.part"; then
        mv "$TARBALL.part" "$TARBALL"
        break
      fi
      rm -f "$TARBALL.part"
    done
  fi
  if [ ! -e "$TARBALL" ]; then
    echo "Failed to download musl $MUSL_VERSION from any mirror" >&2
    exit 1
  fi
  echo "$MUSL_SHA256  $TARBALL" | sha256sum -c -

  BUILD_DIR="$SRC_ROOT/build-$ARCH"
  rm -rf "$BUILD_DIR" "$SRC_ROOT/musl-$MUSL_VERSION"
  tar -xzf "$TARBALL" -C "$SRC_ROOT"
  cp -r "$SRC_ROOT/musl-$MUSL_VERSION" "$BUILD_DIR"

  (
    cd "$BUILD_DIR"
    # --enable-wrapper=no: the musl-gcc/musl-clang wrapper scripts are for
    # driving a *host* compiler at a musl sysroot. Bazel drives clang with
    # an explicit --target/--sysroot instead (see toolchain_flags.bzl), so
    # the wrappers would just be dead files in the output.
    ./configure \
      --target="$MUSL_TARGET" \
      --prefix="$MUSL_DIR" \
      --disable-shared \
      --enable-wrapper=no \
      CC="$CLANG" \
      CFLAGS="--target=$MUSL_TARGET -Os -fPIC" \
      LDFLAGS="-fuse-ld=lld" \
      AR="$CLANG_DIR/bin/llvm-ar" \
      RANLIB="$CLANG_DIR/bin/llvm-ranlib"
    make -j"$(nproc)"
    make install
  )

  install_uapi_shims "$MUSL_DIR"

  # Architecture-specific UAPI, verbatim from the pinned kernel. Adding a new
  # target means adding its asm-<arch> directory to build/toolchain/uapi/ --
  # no discovery pass, no transcribed constants.
  UAPI_SRC="$REPO_ROOT/build/toolchain/uapi"
  if [ ! -d "$UAPI_SRC/asm-$KERNEL_ARCH" ]; then
    echo "No vendored UAPI headers for kernel arch '$KERNEL_ARCH'." >&2
    echo "See $UAPI_SRC/README.md for how to generate them." >&2
    exit 1
  fi
  cp -r "$UAPI_SRC/asm-$KERNEL_ARCH" "$MUSL_DIR/include/asm"
  cp -r "$UAPI_SRC/asm-generic" "$MUSL_DIR/include/asm-generic"
fi

# --- 3. libc++/libc++abi/libunwind, from LLVM source at the same commit as
# the clang binary, compiled against the musl sysroot above ---
if [ ! -e "$LIBCXX_DIR/lib/libc++.a" ]; then
  echo "== Building libc++ for $MUSL_TARGET =="
  SRC_ROOT=/tmp/llvm-src
  SRC="$SRC_ROOT/llvm-project-$LLVM_COMMIT"
  if [ ! -d "$SRC" ]; then
    mkdir -p "$SRC_ROOT"
    curl -fsSL "https://github.com/llvm/llvm-project/archive/${LLVM_COMMIT}.tar.gz" \
      | tar -xz -C "$SRC_ROOT" \
        "llvm-project-$LLVM_COMMIT/compiler-rt" \
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

  build_compiler_rt

  BUILD_DIR="/tmp/libcxx-build-$ARCH"
  rm -rf "$BUILD_DIR"
  mkdir -p "$BUILD_DIR"

  # --unwindlib=none, not libunwind: this build is what *produces* libunwind,
  # so CMake's link probes have to work before it exists. The real build gets
  # --unwindlib=libunwind from toolchain_flags.bzl.
  MUSL_FLAGS="--target=$MUSL_TARGET --sysroot=$MUSL_DIR -fuse-ld=lld -I$SRC/libc"
  MUSL_LINK_FLAGS="$MUSL_FLAGS --rtlib=compiler-rt --unwindlib=none -nostdlib++"

  cmake -GNinja -S "$SRC/runtimes" -B "$BUILD_DIR" \
    -DCMAKE_C_COMPILER="$CLANG" \
    -DCMAKE_CXX_COMPILER="$CLANG_DIR/bin/clang++" \
    -DCMAKE_ASM_COMPILER_TARGET="$MUSL_TARGET" \
    -DCMAKE_AR="$CLANG_DIR/bin/llvm-ar" \
    -DCMAKE_RANLIB="$CLANG_DIR/bin/llvm-ranlib" \
    -DCMAKE_C_COMPILER_TARGET="$MUSL_TARGET" \
    -DCMAKE_CXX_COMPILER_TARGET="$MUSL_TARGET" \
    -DCMAKE_SYSROOT="$MUSL_DIR" \
    -DCMAKE_C_FLAGS="$MUSL_FLAGS" \
    -DCMAKE_CXX_FLAGS="$MUSL_FLAGS" \
    -DCMAKE_EXE_LINKER_FLAGS="$MUSL_LINK_FLAGS" \
    -DCMAKE_SHARED_LINKER_FLAGS="$MUSL_LINK_FLAGS" \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi;libunwind" \
    -DLIBCXXABI_USE_LLVM_UNWINDER=ON \
    -DLIBCXX_CXX_ABI=libcxxabi \
    -DLIBCXX_HAS_MUSL_LIBC=ON \
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

  mkdir -p "$LIBCXX_DIR"
  cp -r "$BUILD_DIR/lib" "$BUILD_DIR/include" "$LIBCXX_DIR/"
fi

# --- 4. Hand the resolved paths to Bazel ---
# BUILD.bazel can't call getenv or resolve the workspace root, and $PREFIX is
# no longer the fixed /opt it used to be, so the concrete paths are written
# out here for it to load(). Regenerated on every run; never checked in.
cat > "$REPO_ROOT/build/toolchain/toolchain_paths.bzl" <<EOF
"""Generated by build/toolchain/setup_toolchain.sh -- do not edit or commit.

Absolute paths to the toolchain this checkout was set up with. Regenerated
on every setup run; see .gitignore.
"""

TOOLCHAIN_PREFIX = "$PREFIX"
CLANG_RESOURCE_DIR = "$CLANG_RESOURCE_DIR"
EOF

echo "== Done: $ARCH toolchain ready =="
echo "  clang:   $CLANG"
echo "  musl:    $MUSL_DIR"
echo "  libc++:  $LIBCXX_DIR"
echo "  paths:   $REPO_ROOT/build/toolchain/toolchain_paths.bzl"
