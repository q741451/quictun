#!/bin/bash
# Merges the profiles a coverage build wrote and reports line coverage of
# the files that differ by platform or that the event loop runs through.
#
# Usage: report.sh <profile directory> <output directory> <binary>...
#
# llvm-profdata and llvm-cov come from Chromium's llvm-code-coverage
# package of the clang setup_toolchain.sh pins, so they read the profile
# format that clang writes; the package is checked against a hash below.
set -euo pipefail

PROFILES=${1:?usage: $0 <profile directory> <output directory> <binary>...}
OUT=${2:?usage: $0 <profile directory> <output directory> <binary>...}
shift 2
[ $# -gt 0 ] || { echo "usage: $0 <profile directory> <output directory> <binary>..." >&2; exit 1; }

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CLANG_PACKAGE_VERSION=$(sed -n 's/^CLANG_PACKAGE_VERSION=//p' "$REPO_ROOT/build/toolchain/setup_toolchain.sh")

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)
    PACKAGE=Linux_x64
    SHA256=2cb5220dceb4be408c306537e83b323219ed0129cf3512fb4bbf49aa0c334b7f ;;
  Darwin-arm64)
    PACKAGE=Mac_arm64
    SHA256=9a2a764f9f2dbb46eba03ed29a87bf55b580a1f7e562ba4002056cb28e2c5902 ;;
  *) echo "No coverage tools pinned for $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

TOOLS=$(mktemp -d)
trap 'rm -rf "$TOOLS"' EXIT
curl -fsSL --retry 3 -o "$TOOLS/cov.tar.xz" \
  "https://commondatastorage.googleapis.com/chromium-browser-clang/$PACKAGE/llvm-code-coverage-$CLANG_PACKAGE_VERSION.tar.xz"
echo "$SHA256  $TOOLS/cov.tar.xz" | shasum -a 256 -c -
tar -xJf "$TOOLS/cov.tar.xz" -C "$TOOLS"

FILES=(
  quiche/quic/core/io/quic_poll_event_loop.cc
  quiche/quic/core/io/socket.cc
  quiche/quic/core/io/socket_posix.inc
  quiche/quic/core/io/socket_win.inc
  quiche/quic/core/io/event_loop_connecting_client_socket.cc
  quiche/quic/core/quic_udp_socket.cc
  quiche/quic/core/quic_udp_socket_posix.inc
  quiche/quic/core/quic_udp_socket_win.inc
  quiche/quic/core/quic_packet_reader.cc
  quiche/quic/core/quic_default_packet_writer.cc
  quiche/quic/tools/quictun_accepted_tcp_socket.cc
  quiche/quic/tools/quictun_client_driver.cc
  quiche/quic/tools/quictun_server_driver.cc
  quiche/quic/tools/quictun_connection_factory.cc
  quiche/quic/tools/quictun_socket_util.cc
  quiche/quic/tools/quictun_platform.cc
  quiche/quic/tools/quictun_tunnel.cc
  quiche/common/quiche_ip_address.cc
  quiche/common/quiche_ip_address_family.cc
)

mkdir -p "$OUT"
"$TOOLS/bin/llvm-profdata" merge -sparse "$PROFILES"/*.profraw -o "$OUT/merged.profdata"
OBJECTS=("$1")
for binary in "${@:2}"; do
  OBJECTS+=(-object="$binary")
done
"$TOOLS/bin/llvm-cov" report "${OBJECTS[@]}" -instr-profile="$OUT/merged.profdata" \
  -compilation-dir="$REPO_ROOT" "${FILES[@]}" > "$OUT/summary.txt"
"$TOOLS/bin/llvm-cov" show "${OBJECTS[@]}" -instr-profile="$OUT/merged.profdata" \
  -compilation-dir="$REPO_ROOT" -show-line-counts-or-regions "${FILES[@]}" > "$OUT/show.txt"
cat "$OUT/summary.txt"
