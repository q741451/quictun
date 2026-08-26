#!/bin/bash
# Systematic sweep for code that compiles differently under a different libc.
#
# Switching sysroots silently changes which #if branches the preprocessor
# takes, and a branch taken wrongly can compile clean and fail only at
# runtime -- see the __GLIBC_PREREQ/accept4 bug that made every accepted TCP
# socket blocking under musl (quiche/quic/core/io/socket_posix.inc).
#
# Rather than grep for known vendor macros and hope the list is complete, this
# derives the list: preprocess the same translation unit against both sysroots,
# diff the resulting macro sets, then report every #if/#ifdef in the tree that
# tests a macro whose definedness or value differs. Anything that survives
# this sweep cannot change branch on a libc swap.
#
# Usage: libc_macro_audit.sh [reference-sysroot]
#   reference-sysroot defaults to the host's glibc (/), i.e. compare musl
#   against what the build used to use.
set -uo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
PREFIX=${QUICTUN_TOOLCHAIN_PREFIX:-$REPO_ROOT/build/toolchain/out}
CLANG="$PREFIX/chromium-clang/bin/clang++"
MUSL_SYSROOT="$PREFIX/musl-x64"
REF_SYSROOT=${1:-/}

# Scan roots: this fork's own code plus the third-party sources that actually
# get compiled into the binaries. Third-party is where this class of bug is
# most expensive -- it is not ours to read line by line, and a mis-taken #if
# branch there surfaces as a runtime misbehaviour with no compile error.
SCAN_ROOTS=("$REPO_ROOT/quiche")
EXTERNAL=$(bazel info output_base 2>/dev/null)/external
for dep in abseil-cpp+ boringssl+ protobuf+ googleurl+ zlib+ com_google_quic_trace; do
  for d in "$EXTERNAL/$dep" "$EXTERNAL/+_repo_rules+$dep"; do
    [ -d "$d" ] && SCAN_ROOTS+=("$d")
  done
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# A TU including every system header the build actually pulls in, so that
# libc-defined macros (not just compiler builtins) land in the macro set.
{
  grep -rhoE '#include <[a-z0-9_/]+\.h>' "${SCAN_ROOTS[@]}" \
    --include=*.cc --include=*.h --include=*.inc 2>/dev/null
  printf '#include <features.h>\n'
} | sort -u > "$WORK/includes.raw"

# Drop headers that don't exist in both sysroots -- their absence is itself
# reported separately below, and a missing include would abort the dump.
: > "$WORK/tu.cc"
: > "$WORK/missing.txt"
while read -r line; do
  hdr=$(printf '%s' "$line" | sed 's/#include <//; s/>//')
  in_ref=0; in_musl=0
  [ -e "$REF_SYSROOT/usr/include/$hdr" ] || [ -e "$REF_SYSROOT/usr/include/x86_64-linux-gnu/$hdr" ] && in_ref=1
  [ -e "$MUSL_SYSROOT/include/$hdr" ] && in_musl=1
  if [ "$in_ref" = 1 ] && [ "$in_musl" = 1 ]; then
    printf '#include <%s>\n' "$hdr" >> "$WORK/tu.cc"
  elif [ "$in_ref" != "$in_musl" ]; then
    printf '%-40s ref=%s musl=%s\n' "$hdr" "$in_ref" "$in_musl" >> "$WORK/missing.txt"
  fi
done < "$WORK/includes.raw"

dump_macros() {  # $1=target $2=sysroot $3=out
  "$CLANG" --target="$1" --sysroot="$2" -D_GNU_SOURCE -std=c++20 \
    -dM -E -x c++ "$WORK/tu.cc" 2>/dev/null \
    | sed 's/^#define //' | sort > "$3"
}

dump_macros x86_64-unknown-linux-gnu "$REF_SYSROOT" "$WORK/ref.txt"
dump_macros x86_64-linux-musl        "$MUSL_SYSROOT" "$WORK/musl.txt"

# Function-like macros come out of -dM as `NAME(a,b)`; strip the parameter
# list or the name never matches a #if that references it -- which silently
# hid __GLIBC_PREREQ, the exact macro this script was written to catch.
macro_names() { cut -d' ' -f1 "$1" | sed 's/(.*//' | sort -u; }
macro_names "$WORK/ref.txt"  > "$WORK/ref.names"
macro_names "$WORK/musl.txt" > "$WORK/musl.names"

comm -23 "$WORK/ref.names" "$WORK/musl.names" > "$WORK/only_ref.txt"
comm -13 "$WORK/ref.names" "$WORK/musl.names" > "$WORK/only_musl.txt"
# Same name, different value. Compare fully-expanded results rather than the
# raw #define text: glibc spells SOCK_NONBLOCK as O_NONBLOCK and musl as
# 04000, which is the same value and not a difference worth reporting.
comm -12 "$WORK/ref.names" "$WORK/musl.names" > "$WORK/common.names"
grep -E '^(SOCK_|SO_|MSG_|IPV?6?_|UDP_|TCP_|SCM_|POLL|O_|F_|AF_|__)' \
  "$WORK/common.names" | grep -vE '\(' > "$WORK/probe.names" || true

expand_values() {  # $1=target $2=sysroot $3=out
  {
    cat "$WORK/tu.cc"
    while read -r n; do printf 'QUICTUN_PROBE %s = %s;\n' "$n" "$n"; done \
      < "$WORK/probe.names"
  } > "$WORK/probe.cc"
  "$CLANG" --target="$1" --sysroot="$2" -D_GNU_SOURCE -std=c++20 \
    -E -x c++ "$WORK/probe.cc" 2>/dev/null \
    | grep '^QUICTUN_PROBE ' | sed 's/^QUICTUN_PROBE //; s/;$//' | sort > "$3"
}
expand_values x86_64-unknown-linux-gnu "$REF_SYSROOT" "$WORK/ref.vals"
expand_values x86_64-linux-musl        "$MUSL_SYSROOT" "$WORK/musl.vals"
diff "$WORK/ref.vals" "$WORK/musl.vals" 2>/dev/null \
  | grep '^<' | sed 's/^< //' | cut -d' ' -f1 | sort -u \
  > "$WORK/differing_values.txt" || true

cat "$WORK/only_ref.txt" "$WORK/only_musl.txt" "$WORK/differing_values.txt" \
  | sort -u > "$WORK/suspect.txt"

echo "=================================================================="
echo " libc macro audit:  ref=$REF_SYSROOT"
echo "                   musl=$MUSL_SYSROOT"
echo "=================================================================="
printf 'scan roots:\n'
for r in "${SCAN_ROOTS[@]}"; do printf '  %s\n' "$(basename "$r")"; done
printf 'macros only in ref : %d\n' "$(wc -l < "$WORK/only_ref.txt")"
printf 'macros only in musl: %d\n' "$(wc -l < "$WORK/musl.names" >/dev/null; wc -l < "$WORK/only_musl.txt")"
printf 'same name, different value: %d\n' "$(wc -l < "$WORK/differing_values.txt")"
echo

if [ -s "$WORK/missing.txt" ]; then
  echo "--- headers present in only one sysroot -------------------------"
  cat "$WORK/missing.txt"
  echo
fi

echo "--- conditional compilation that depends on a differing macro ----"
echo "    (these are the sites that can change behaviour on a libc swap)"
echo
FOUND=0
while read -r macro; do
  [ -z "$macro" ] && continue
  hits=$(grep -rn --include=*.cc --include=*.h --include=*.inc \
           -E "^[[:space:]]*#[[:space:]]*(if|elif|ifdef|ifndef).*\b$macro\b" \
           "${SCAN_ROOTS[@]}" 2>/dev/null \
           | grep -vE "_test\.cc|/test/|_unittest\.cc")
  if [ -n "$hits" ]; then
    FOUND=1
    printf '### %s\n' "$macro"
    printf '%s\n' "$hits" | sed 's|'"$REPO_ROOT"'/||' | sed 's/^/    /'
    echo
  fi
done < "$WORK/suspect.txt"

[ "$FOUND" = 0 ] && echo "    (none -- nothing scanned tests a macro that differs)"
exit 0
