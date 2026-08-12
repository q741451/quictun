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

# --quic_conn pooling, interleaved into a deliberately adversarial subset
# of conditions rather than the full 5x2 cross (keeps the matrix's run
# time sane) -- each pairing targets a specific pooling-path risk area:
#   clean+1, clean+3          baseline pooling sanity, light vs. heavy
#   quic_bad+3                loss/retransmission storms while several
#                              tunnels genuinely share one connection
#                              (heaviest fan-in for the reentrant-Close()
#                              paths fixed in 715a5f926)
#   client_tcp_bad+1          TCP-side resets while pooled (StartTunnel()
#                              reentrancy fix's exact territory)
#   server_tcp_bad+3          target-side flakiness while heavily pooled
#                              (started_ flag's async-dial-out race)
#   combo_all_bad+1/3         everything bad at once, light and heavy
#                              pooling both
CLIENT_POOL_COMBOS="clean:1 clean:3 quic_bad:3 client_tcp_bad:1 server_tcp_bad:3 combo_all_bad:1 combo_all_bad:3"
for combo in $CLIENT_POOL_COMBOS; do
  cond="${combo%%:*}"
  qc="${combo##*:}"
  echo "=== client_chaos_test.py --condition=$cond --quic-conn=$qc ===" | tee -a "$RESULTS"
  python3 -u client_chaos_test.py --condition="$cond" --quic-conn="$qc" >> "$RESULTS" 2>&1
  echo "exit=$? for client_chaos_test.py --condition=$cond --quic-conn=$qc" | tee -a "$RESULTS"
done

# Same pooling dimension on the server side, a smaller sample (each
# server_chaos_test.py round already fans multiple concurrent TCP flows
# into every "real" client, so pooling's effect shows up even with fewer
# condition pairings than the client side needed).
SERVER_POOL_COMBOS="clean:1 quic_bad:3 combo_all_bad:1"
for combo in $SERVER_POOL_COMBOS; do
  cond="${combo%%:*}"
  qc="${combo##*:}"
  echo "=== server_chaos_test.py --condition=$cond --quic-conn=$qc ===" | tee -a "$RESULTS"
  python3 -u server_chaos_test.py --condition="$cond" --quic-conn="$qc" >> "$RESULTS" 2>&1
  echo "exit=$? for server_chaos_test.py --condition=$cond --quic-conn=$qc" | tee -a "$RESULTS"
done

# Deterministic reentrancy regression, targeted (not incidental like the
# chaos suites above) at the exact crashes fixed in 715a5f926: concurrent
# TCP bursts through quictun_client while quictun_server gets killed mid-
# burst, repeatedly -- see pool_reentrancy_test.py's own top comment.
# quic-conn=0 is a control (same trigger mechanism, but no sibling tunnel
# for the cross-tunnel reentrancy class of those fixes to even be
# possible against) -- 1 and 3 are two different pool sizes actually
# exercising it.
for qc in 0 1 3; do
  echo "=== pool_reentrancy_test.py --quic-conn=$qc ===" | tee -a "$RESULTS"
  python3 -u pool_reentrancy_test.py --quic-conn="$qc" >> "$RESULTS" 2>&1
  echo "exit=$? for pool_reentrancy_test.py --quic-conn=$qc" | tee -a "$RESULTS"
done

# Sustained-duration leak check: everything above compares one before/
# after snapshot from a run lasting well under a minute, long enough to
# catch a leak that's large per-cycle but not one that's merely nonzero
# per-cycle -- the harder, more realistic case for a feature specifically
# about keeping connections open and reused over time. 120s here (shorter
# than the script's own 180s default) to keep this matrix's total runtime
# sane; run pool_soak_test.py directly with a much longer --duration
# (e.g. 1800) for a deeper check when actually chasing a suspected slow
# leak.
echo "=== pool_soak_test.py --duration=120 ===" | tee -a "$RESULTS"
python3 -u pool_soak_test.py --duration=120 >> "$RESULTS" 2>&1
echo "exit=$? for pool_soak_test.py --duration=120" | tee -a "$RESULTS"

# Does --quic_conn pooling actually pool -- N concurrent TCP flows really
# sharing at most N underlying QUIC connections, not just "still working"
# under pooling (everything above already covers that). No condition
# variants: this is a structural property of pool_slots_' own selection
# logic, not something network chaos changes.
echo "=== pool_cap_test.py ===" | tee -a "$RESULTS"
python3 -u pool_cap_test.py >> "$RESULTS" 2>&1
echo "exit=$? for pool_cap_test.py" | tee -a "$RESULTS"

# --quic_conn pooling against QUIC's own real, protocol-level
# max_streams-per-connection ceiling (quictun never touches this --
# QUICTUN_TEST_MAX_STREAMS's own comment in quictun_server_driver.cc):
# streams beyond the cap should queue cleanly and get serviced once an
# earlier one closes and frees credit, not error or wedge the connection.
# Needs -DQUICTUN_TEST_BUILD the same way writeblock_fault_test.py below
# does -- but unlike that one, this fails loudly rather than silently
# passing without it (QUICTUN_TEST_MAX_STREAMS compiled out means the
# server falls back to the real 100-stream default, so all 12 held
# connections below would succeed immediately instead of 5, failing
# PHASE 1's assertion).
echo "=== max_streams_test.py ===" | tee -a "$RESULTS"
python3 -u max_streams_test.py >> "$RESULTS" 2>&1
echo "exit=$? for max_streams_test.py" | tee -a "$RESULTS"

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

# Same again, pooled: RearmOnBlockPacketWriter's recovery needs to be
# connection-level, unsticking every stream queued behind the shared
# writer -- not just whichever one the fault-injection counter happened
# to land on. Untested until now -- every writeblock scenario above only
# ever had the one stream.
echo "=== writeblock_fault_test.py --side=both --quic-conn=1 ===" | tee -a "$RESULTS"
python3 -u writeblock_fault_test.py --side=both --quic-conn=1 >> "$RESULTS" 2>&1
echo "exit=$? for writeblock_fault_test.py --side=both --quic-conn=1" | tee -a "$RESULTS"

# --target refusing the TCP connect (ECONNREFUSED) -- another coverage gap
# (QuictunServerConnection::ConnectComplete()'s failure branch), matching
# the ordinary operational case of the backend service being down.
echo "=== target_unreachable_test.py ===" | tee -a "$RESULTS"
python3 -u target_unreachable_test.py >> "$RESULTS" 2>&1
echo "exit=$? for target_unreachable_test.py" | tee -a "$RESULTS"

# Same, pooled: does one stream's dial failure wedge/crash the shared
# connection for the next stream assigned to it? The unpooled run above
# can't exercise this at all -- every attempt there gets its own fresh
# connection no matter what happened to the previous one.
echo "=== target_unreachable_test.py --quic-conn=2 ===" | tee -a "$RESULTS"
python3 -u target_unreachable_test.py --quic-conn=2 >> "$RESULTS" 2>&1
echo "exit=$? for target_unreachable_test.py --quic-conn=2" | tee -a "$RESULTS"

# IPv6 dual-stack --listen ([::]) reached by an IPv4 peer -- another
# coverage gap (AdaptPeerAddressForListenSocket() in
# quictun_server_driver.cc); every other test's --listen is plain IPv4.
echo "=== dualstack_ipv6_test.py ===" | tee -a "$RESULTS"
python3 -u dualstack_ipv6_test.py >> "$RESULTS" 2>&1
echo "exit=$? for dualstack_ipv6_test.py" | tee -a "$RESULTS"

echo "=== dualstack_ipv6_test.py --quic-conn=2 ===" | tee -a "$RESULTS"
python3 -u dualstack_ipv6_test.py --quic-conn=2 >> "$RESULTS" 2>&1
echo "exit=$? for dualstack_ipv6_test.py --quic-conn=2" | tee -a "$RESULTS"

echo "=== MATRIX COMPLETE ===" | tee -a "$RESULTS"
echo "Full results: $RESULTS"
