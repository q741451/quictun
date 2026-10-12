#!/bin/bash
# The Windows counterpart of setup_toolchain.sh and setup_toolchain_macos.sh:
# the same Chromium-pinned clang, driven as clang-cl/lld-link, and libc++
# built from LLVM source at the same commit, statically linked into the
# binary along with the static MSVC runtime (/MT). Windows binaries are
# cross-built on Linux, the way Chromium cross-builds them.
#
# Microsoft's SDK and C runtime are fetched by xwin from Microsoft's own
# Visual Studio manifest, at pinned versions, and the unpacked tree is checked
# against a hash recorded below: anything else Microsoft might serve under
# the same version numbers fails the setup instead of reaching a build. They
# may only be used to build, not redistributed, so they are never committed;
# CI downloads them and caches the result like the rest of the toolchain.
#
# What is shared with setup_toolchain.sh is read out of it rather than
# repeated, as setup_toolchain_macos.sh does. The clang itself is the Linux
# package that setup_toolchain.sh installs (it carries clang-cl, lld-link and
# llvm-ml), so run `setup_toolchain.sh x64` first -- Bazel needs that one
# anyway, for the build-time tools it runs on the Linux host.
#
# Usage: setup_toolchain_windows.sh <x64>
#
# Installs under $QUICTUN_TOOLCHAIN_PREFIX, defaulting to this repo's
# build/toolchain/out/, next to the Linux toolchain:
#   $PREFIX/winsdk/                 (MSVC CRT + Windows SDK, as xwin lays out)
#   $PREFIX/libcxx-windows-<arch>/  (static libc++)
#   $PREFIX/windows-bin/            (llvm-lib, llvm-ar under the name that
#                                    makes it act as lib.exe)
# and writes the resolved paths, and the --target of every architecture, to
# build/toolchain/windows/toolchain_paths.bzl.
set -euo pipefail

ARCH=${1:-}

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
PREFIX=${QUICTUN_TOOLCHAIN_PREFIX:-$REPO_ROOT/build/toolchain/out}
BUILD_ROOT=$REPO_ROOT/build/toolchain/.build
FILE_PREFIX_MAP="/clang:-ffile-prefix-map=$BUILD_ROOT/="

# --- Pins ---
# Shared with Linux, read from setup_toolchain.sh's own assignments.
eval "$(grep -E '^(LLVM_COMMIT|LLVM_SRC_SHA256)=' \
  "$REPO_ROOT/build/toolchain/setup_toolchain.sh")"
if [ -z "${LLVM_COMMIT:-}" ] || [ -z "${LLVM_SRC_SHA256:-}" ]; then
  echo "Could not read the LLVM pins from setup_toolchain.sh" >&2
  exit 1
fi
# xwin, the tool that fetches and lays out the SDK and CRT.
XWIN_VERSION=0.10.0
XWIN_SHA256=d870eb4b2f390878af6da1ccd3cf321d22fcb72720984853b4be732ae597fc88
# The MSVC CRT of Visual Studio 2022 17.14 and the Windows 11 24H2 SDK, both
# long in service. The SDK decides which headers and import libraries exist,
# not which Windows the binaries need: that is WINDOWS_MIN_VERSION below.
MSVC_MANIFEST_VERSION=17
MSVC_CRT_VERSION=14.44.17.14
WINDOWS_SDK_VERSION=10.0.26100
# sha256 over the unpacked tree (every file's path and sha256, every
# symlink's path and target, sorted); see tree_hash below. The tree holds the
# libraries of every architecture in ALL_ARCHES, so adding one changes it.
WINSDK_TREE_SHA256=98e229f785c3745b0be0635d13072641ee597081de70224defffee420320c5e5
# Oldest Windows the binaries run on: Windows 10 2004. WSAPoll does not
# report a failed non-blocking connect() before it, which quictun_server's
# connect to --target relies on; see quictun's startup check. As a
# _WIN32_WINNT value Windows 10 has a single one, 0x0A00.
WINDOWS_MIN_VERSION=10.0
WIN32_WINNT=0x0A00

# This repo's arch name -> clang's --target. The single source of the
# triples: BUILD.bazel reads them through the generated toolchain_paths.bzl,
# as the Linux and macOS toolchains do.
arch_windows_target() {
  case "$1" in
    x64) echo x86_64-pc-windows-msvc ;;
  esac
}
# ... and the matching xwin --arch and SDK library directory name.
arch_xwin_arch() {
  case "$1" in
    x64) echo x86_64 ;;
  esac
}

ALL_ARCHES="x64"

WINDOWS_TARGET=$(arch_windows_target "$ARCH")
if [ -z "$WINDOWS_TARGET" ]; then
  echo "Usage: $0 <$(echo "$ALL_ARCHES" | tr ' ' '|')>" >&2
  exit 1
fi
# The SDK and CRT are fetched once for every architecture, as one tree: the
# headers are shared, and only lib/<arch> differs.
WINSDK_XWIN_ARCHES=$(for a in $ALL_ARCHES; do arch_xwin_arch "$a"; done)

CLANG_DIR="$PREFIX/chromium-clang"
if [ ! -x "$CLANG_DIR/bin/clang-cl" ]; then
  echo "No clang-cl in $CLANG_DIR: run setup_toolchain.sh x64 first." >&2
  exit 1
fi
CLANG_RESOURCE_DIR=$("$CLANG_DIR/bin/clang" -print-resource-dir)
WINSDK_DIR="$PREFIX/winsdk"
LIBCXX_DIR="$PREFIX/libcxx-windows-$ARCH"
BIN_DIR="$PREFIX/windows-bin"
mkdir -p "$PREFIX" "$BUILD_ROOT" "$BIN_DIR"

# As abi_stamp_check in setup_toolchain.sh: discard a libc++ built for a
# different target or minimum Windows, which the stages below would
# otherwise reuse. For incremental local builds; CI's cache key hashes this
# script.
STAMP="$PREFIX/.abi-stamp-windows-$ARCH"
WANT="$WINDOWS_TARGET $WIN32_WINNT"
if [ -e "$STAMP" ] && [ "$(cat "$STAMP")" != "$WANT" ]; then
  echo "== Target changed for $ARCH ($(cat "$STAMP") -> $WANT): discarding its libc++ =="
  rm -rf "$LIBCXX_DIR" "$BUILD_ROOT/libcxx-windows-$ARCH"
fi
printf '%s' "$WANT" > "$STAMP"

# llvm-ar acts as lib.exe when invoked as llvm-lib; the package only ships
# the canonical binary (setup_toolchain.sh does the same for llvm-ranlib).
ln -sf "$CLANG_DIR/bin/llvm-ar" "$BIN_DIR/llvm-lib"

tree_hash() {
  (cd "$1" && find . \( -type f -o -type l \) -print0 | LC_ALL=C sort -z |
    while IFS= read -r -d '' f; do
      if [ -L "$f" ]; then
        printf 'L %s -> %s\n' "$f" "$(readlink "$f")"
      else
        printf 'F %s %s\n' "$f" "$(sha256sum < "$f" | cut -d' ' -f1)"
      fi
    done) | sha256sum | cut -d' ' -f1
}

# --- 1. The MSVC CRT and Windows SDK, through a pinned xwin ---
# Refetched when ALL_ARCHES changes, as abi_stamp_check does for libc++, or
# a tree fetched for fewer architectures would be kept.
WINSDK_STAMP="$PREFIX/.winsdk-arches"
if [ -e "$WINSDK_STAMP" ] && [ "$(cat "$WINSDK_STAMP")" != "$WINSDK_XWIN_ARCHES" ]; then
  echo "== Architectures changed ($(cat "$WINSDK_STAMP") -> $WINSDK_XWIN_ARCHES): refetching the SDK =="
  rm -rf "$WINSDK_DIR"
fi
if [ ! -d "$WINSDK_DIR" ]; then
  echo "== Fetching MSVC CRT $MSVC_CRT_VERSION and Windows SDK $WINDOWS_SDK_VERSION =="
  XWIN_DIR="$BUILD_ROOT/xwin-$XWIN_VERSION"
  if [ ! -x "$XWIN_DIR/xwin" ]; then
    TARBALL="$BUILD_ROOT/xwin-$XWIN_VERSION.tar.gz"
    curl -fsSL --retry 3 -o "$TARBALL" \
      "https://github.com/Jake-Shadle/xwin/releases/download/$XWIN_VERSION/xwin-$XWIN_VERSION-x86_64-unknown-linux-musl.tar.gz"
    echo "$XWIN_SHA256  $TARBALL" | sha256sum -c -
    mkdir -p "$XWIN_DIR"
    tar -xzf "$TARBALL" -C "$XWIN_DIR" --strip-components=1
    rm -f "$TARBALL"
  fi
  # Unpacked next to the final location and moved there only once its hash
  # matches, so a failed or tampered fetch never leaves a usable-looking tree.
  rm -rf "$WINSDK_DIR.new"
  "$XWIN_DIR/xwin" --accept-license --http-retry 3 \
    --cache-dir "$BUILD_ROOT/xwin-cache" \
    --manifest-version "$MSVC_MANIFEST_VERSION" \
    --crt-version "$MSVC_CRT_VERSION" \
    --sdk-version "$WINDOWS_SDK_VERSION" \
    --arch "$(echo $WINSDK_XWIN_ARCHES | tr ' ' ',')" \
    splat --output "$WINSDK_DIR.new"
  GOT=$(tree_hash "$WINSDK_DIR.new")
  if [ "$GOT" != "$WINSDK_TREE_SHA256" ]; then
    echo "Windows SDK/CRT tree hash is $GOT, expected $WINSDK_TREE_SHA256." >&2
    exit 1
  fi
  mv "$WINSDK_DIR.new" "$WINSDK_DIR"
fi
printf '%s' "$WINSDK_XWIN_ARCHES" > "$WINSDK_STAMP"

# Library names that dependencies spell in a casing xwin's own symlinks do
# not cover, linked the way xwin fixes casing (README: splat's symlinks), on
# top of the verified tree. Chromium solves the same problem with a
# case-insensitive ciopfs mount (build/vs_toolchain.py) instead. A new
# spelling in a dependency fails the link with "could not open", rather than
# being guessed at here.
#   Ws2_32.lib   BoringSSL crypto/bio/socket.cc, #pragma comment(lib)
#   Shell32.lib  protobuf build_defs/cpp_opts.bzl, linkopts
for xwin_arch in $WINSDK_XWIN_ARCHES; do
  ln -sfn ws2_32.lib "$WINSDK_DIR/sdk/lib/um/$xwin_arch/Ws2_32.lib"
  ln -sfn shell32.lib "$WINSDK_DIR/sdk/lib/um/$xwin_arch/Shell32.lib"
done

# The SDK's include directories, for the libc++ build below. Bazel gets the
# same list from windows/toolchain_flags.bzl, which derives it from
# WINSDK_DIR in toolchain_paths.bzl.
SDK_COMPILE_FLAGS="/imsvc$WINSDK_DIR/crt/include /imsvc$WINSDK_DIR/sdk/include/ucrt /imsvc$WINSDK_DIR/sdk/include/um /imsvc$WINSDK_DIR/sdk/include/shared"

# --- 2. LLVM source, the same commit setup_toolchain.sh builds from ---
SRC_ROOT=$BUILD_ROOT/llvm-src
SRC="$SRC_ROOT/llvm-project-$LLVM_COMMIT"
if [ ! -d "$SRC" ]; then
  mkdir -p "$SRC_ROOT"
  TARBALL="$SRC_ROOT/llvm-$LLVM_COMMIT.tar.gz"
  curl -fsSL --retry 3 -o "$TARBALL" \
    "https://github.com/llvm/llvm-project/archive/${LLVM_COMMIT}.tar.gz"
  echo "$LLVM_SRC_SHA256  $TARBALL" | sha256sum -c -
  tar -xzf "$TARBALL" -C "$SRC_ROOT" \
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
  rm -f "$TARBALL"
fi

# --- 3. libc++, static, on the static MSVC runtime ---
# As in Chromium's Windows build: libc++ over vcruntime, which provides the
# C++ ABI layer (exceptions, RTTI) that libc++abi does on Linux and macOS,
# so there is no libc++abi here. /MT, the static runtime, so the binaries
# depend on no runtime DLL. CMake's probes only compile (STATIC_LIBRARY),
# since linking a probe would need tools (mt.exe) this toolchain lacks.
if [ ! -e "$LIBCXX_DIR/lib/libc++.lib" ]; then
  echo "== Building libc++ for $WINDOWS_TARGET =="
  BUILD_DIR="$BUILD_ROOT/libcxx-windows-$ARCH"
  rm -rf "$BUILD_DIR"
  mkdir -p "$BUILD_DIR"

  FLAGS="--target=$WINDOWS_TARGET /D_WIN32_WINNT=$WIN32_WINNT /DWINVER=$WIN32_WINNT $SDK_COMPILE_FLAGS $FILE_PREFIX_MAP"
  cmake -GNinja -S "$SRC/runtimes" -B "$BUILD_DIR" \
    -DCMAKE_SYSTEM_NAME=Windows \
    -DCMAKE_SYSTEM_PROCESSOR=AMD64 \
    -DCMAKE_C_COMPILER="$CLANG_DIR/bin/clang-cl" \
    -DCMAKE_CXX_COMPILER="$CLANG_DIR/bin/clang-cl" \
    -DCMAKE_LINKER="$CLANG_DIR/bin/lld-link" \
    -DCMAKE_AR="$BIN_DIR/llvm-lib" \
    -DCMAKE_C_COMPILER_TARGET="$WINDOWS_TARGET" \
    -DCMAKE_CXX_COMPILER_TARGET="$WINDOWS_TARGET" \
    -DCMAKE_C_FLAGS="$FLAGS" \
    -DCMAKE_CXX_FLAGS="$FLAGS" \
    -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
    -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_ENABLE_RUNTIMES="libcxx" \
    -DLIBCXX_CXX_ABI=vcruntime \
    -DLIBCXX_ENABLE_SHARED=OFF \
    -DLIBCXX_ENABLE_STATIC=ON \
    -DLIBCXX_INCLUDE_TESTS=OFF \
    -DLIBCXX_INCLUDE_BENCHMARKS=OFF \
    -DLLVM_INCLUDE_TESTS=OFF

  ninja -C "$BUILD_DIR" -j"$(nproc)" cxx

  mkdir -p "$LIBCXX_DIR"
  cp -r "$BUILD_DIR/lib" "$BUILD_DIR/include" "$LIBCXX_DIR/"
fi

# --- 4. Hand the resolved paths to Bazel ---
cat > "$REPO_ROOT/build/toolchain/windows/toolchain_paths.bzl" <<EOF
"""Generated by build/toolchain/setup_toolchain_windows.sh -- do not edit or commit."""

TOOLCHAIN_PREFIX = "$PREFIX"
CLANG_RESOURCE_DIR = "$CLANG_RESOURCE_DIR"
WINSDK_DIR = "$WINSDK_DIR"
WIN32_WINNT = "$WIN32_WINNT"
WINDOWS_MIN_VERSION = "$WINDOWS_MIN_VERSION"

# Every architecture's clang --target, not just the one just set up, and
# its directory name in the SDK's lib/ trees.
WINDOWS_TARGETS = {
$(for a in $ALL_ARCHES; do printf '    "%s": "%s",\n' "$a" "$(arch_windows_target "$a")"; done)
}
WINDOWS_SDK_ARCHES = {
$(for a in $ALL_ARCHES; do printf '    "%s": "%s",\n' "$a" "$(arch_xwin_arch "$a")"; done)
}
EOF

echo "== Done: Windows $ARCH toolchain ready =="
echo "  clang-cl: $CLANG_DIR/bin/clang-cl"
echo "  sdk:      $WINSDK_DIR (CRT $MSVC_CRT_VERSION, SDK $WINDOWS_SDK_VERSION)"
echo "  libc++:   $LIBCXX_DIR"
