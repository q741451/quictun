#!/bin/bash
# Regenerates the vendored <asm/*> UAPI headers in this directory from an
# unmodified upstream kernel tarball, using the kernel's own
# `make headers_install`. Nothing here is written by hand -- see README.md.
#
# Run this to bump KERNEL_VERSION, or to add an architecture (append it to
# ARCHES below; the name is the kernel's own ARCH=, e.g. arm64/arm/mips/riscv).
#
# Usage: ./regenerate.sh
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

KERNEL_VERSION=6.18.46
KERNEL_SHA256=f5d44b93808b02cc2969c5404ba081d97523719c9fd2ba2de6db318b4141cca0
ARCHES=(x86 arm64 arm mips riscv loongarch)
# asm-generic is shared by every architecture's asm/, so one copy is taken
# from whichever arch is listed first.
GENERIC_FROM=${ARCHES[0]}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

TARBALL="$WORK/linux-$KERNEL_VERSION.tar.xz"
MAJOR=${KERNEL_VERSION%%.*}
echo "== Downloading linux-$KERNEL_VERSION =="
curl -fsSL --retry 3 \
  "https://cdn.kernel.org/pub/linux/kernel/v${MAJOR}.x/linux-$KERNEL_VERSION.tar.xz" \
  -o "$TARBALL"
echo "$KERNEL_SHA256  $TARBALL" | sha256sum -c -

echo "== Extracting =="
tar xf "$TARBALL" -C "$WORK"
SRC="$WORK/linux-$KERNEL_VERSION"

for arch in "${ARCHES[@]}"; do
  echo "== headers_install ARCH=$arch =="
  make -C "$SRC" headers_install ARCH="$arch" \
    INSTALL_HDR_PATH="$WORK/out/$arch" >/dev/null
  rm -rf "asm-$arch"
  cp -r "$WORK/out/$arch/include/asm" "asm-$arch"
done

rm -rf asm-generic
cp -r "$WORK/out/$GENERIC_FROM/include/asm-generic" asm-generic

echo
echo "== Done. Update README.md's provenance block if the version changed. =="
du -sh asm-* | sort -k2
