#!/bin/bash
# Full regression matrix: both chaos test suites across all 5 network
# conditions, before any push -- per standing rule.
#
# bazel-bin's quictun_client/quictun_server must be built with
# -DQUICTUN_TEST_BUILD (e.g. `bazel build -c opt
# --copt=-DQUICTUN_TEST_BUILD //quiche:quictun_client //quiche:quictun_server`)
# for the writeblock_fault_test.py runs below to mean anything --
# FaultInjectingPacketWriter (and the QUICTUN_INJECT_WRITE_BLOCK_AFTER env
# var it reads) doesn't exist at all in a plain build, so those runs would
# silently PASS without ever actually injecting a block. The other tests
# (server_chaos_test.py, client_chaos_test.py) work fine against either.
#
# If COVERAGE_DIR is set in the environment, every quictun_client/
# quictun_server subprocess spawned by these scripts inherits
# LLVM_PROFILE_FILE (Python's subprocess.Popen inherits the parent's full
# environment when its own `env=` isn't overridden, which none of these
# scripts' start_proc() helpers do) -- requires bazel-bin's quictun_client/
# quictun_server to already be built with -fprofile-instr-generate
# -fcoverage-mapping -fprofile-continuous -DQUICTUN_COVERAGE_BUILD (see
# this directory's README.md).
set -u
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -n "${COVERAGE_DIR:-}" ]; then
  mkdir -p "$COVERAGE_DIR"
  export LLVM_PROFILE_FILE="$COVERAGE_DIR/coverage-%p.profraw"
  echo "COVERAGE_DIR set -- LLVM_PROFILE_FILE=$LLVM_PROFILE_FILE"
fi
CONDITIONS="clean quic_bad client_tcp_bad server_tcp_bad combo_all_bad"
RESULTS="${MATRIX_RESULTS:-/tmp/quictun_matrix_results.txt}"
> "$RESULTS"

for cond in $CONDITIONS; do
  echo "=== server_chaos_test.py --condition=$cond ===" | tee -a "$RESULTS"
  python3 -u server_chaos_test.py --condition="$cond" >> "$RESULTS" 2>&1
  echo "exit=$? for server_chaos_test.py --condition=$cond" | tee -a "$RESULTS"
done

for cond in $CONDITIONS; do
  echo "=== client_chaos_test.py --condition=$cond ===" | tee -a "$RESULTS"
  python3 -u client_chaos_test.py --condition="$cond" >> "$RESULTS" 2>&1
  echo "exit=$? for client_chaos_test.py --condition=$cond" | tee -a "$RESULTS"
done

# Deterministic write-block fault injection (see writeblock_fault_test.py's
# own top-of-file comment for why this exists as a separate, non-network
# dimension): covers the write-blocked-forever bug fixed by
# RearmOnBlockPacketWriter, on each endpoint independently and together.
for side in client server both; do
  echo "=== writeblock_fault_test.py --side=$side ===" | tee -a "$RESULTS"
  python3 -u writeblock_fault_test.py --side="$side" >> "$RESULTS" 2>&1
  echo "exit=$? for writeblock_fault_test.py --side=$side" | tee -a "$RESULTS"
done

# Same, but with --so_txtime (QuicGsoBatchWriter) -- coverage showed this
# whole path, including RearmOnBlockPacketWriter's Flush()-based block
# detection, was never exercised by anything above.
echo "=== writeblock_fault_test.py --side=both --so-txtime ===" | tee -a "$RESULTS"
python3 -u writeblock_fault_test.py --side=both --so-txtime >> "$RESULTS" 2>&1
echo "exit=$? for writeblock_fault_test.py --side=both --so-txtime" | tee -a "$RESULTS"

# --target refusing the TCP connect (ECONNREFUSED) -- another coverage gap
# (QuictunServerConnection::ConnectComplete()'s failure branch), matching
# the ordinary operational case of the backend service being down.
echo "=== target_unreachable_test.py ===" | tee -a "$RESULTS"
python3 -u target_unreachable_test.py >> "$RESULTS" 2>&1
echo "exit=$? for target_unreachable_test.py" | tee -a "$RESULTS"

# IPv6 dual-stack --listen ([::]) reached by an IPv4 peer -- another
# coverage gap (AdaptPeerAddressForListenSocket() in
# quictun_server_driver.cc); every other test's --listen is plain IPv4.
echo "=== dualstack_ipv6_test.py ===" | tee -a "$RESULTS"
python3 -u dualstack_ipv6_test.py >> "$RESULTS" 2>&1
echo "exit=$? for dualstack_ipv6_test.py" | tee -a "$RESULTS"

echo "=== MATRIX COMPLETE ===" | tee -a "$RESULTS"
echo "Full results: $RESULTS"
