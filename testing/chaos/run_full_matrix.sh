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

# Non-default pool shapes, as cond:conn_per_udp:udp_socket, interleaved
# into a deliberately adversarial subset of conditions rather than the
# full cross (keeps the matrix's run time sane). The loop above already
# covered every condition at the 1:1 default, so each entry here varies at
# least one dimension: conn_per_udp>1 spreads tunnels over more
# connections (lighter fan-in per connection), udp_socket>1 over more
# sockets and writers. Conditions chosen for what they stress:
#   quic_bad        loss/retransmission storms across a shared connection
#                    (heaviest fan-in for the reentrant-Close() paths
#                    fixed in 715a5f926)
#   client_tcp_bad  TCP-side resets (StartTunnel() reentrancy fix's
#                    exact territory)
#   server_tcp_bad  target-side flakiness (started_ flag's async-dial-out
#                    race)
#   combo_all_bad   everything bad at once, both shapes
CLIENT_POOL_COMBOS="clean:3:1 clean:1:2 quic_bad:3:1 quic_bad:1:2 client_tcp_bad:1:2 server_tcp_bad:3:1 combo_all_bad:1:2 combo_all_bad:3:1"
for combo in $CLIENT_POOL_COMBOS; do
  cond="${combo%%:*}"
  rest="${combo#*:}"
  cpu="${rest%%:*}"
  us="${rest##*:}"
  desc="--condition=$cond --conn-per-udp=$cpu --udp-socket=$us"
  echo "=== client_chaos_test.py $desc ===" | tee -a "$RESULTS"
  python3 -u client_chaos_test.py --condition="$cond" --conn-per-udp="$cpu" \
      --udp-socket="$us" >> "$RESULTS" 2>&1
  echo "exit=$? for client_chaos_test.py $desc" | tee -a "$RESULTS"
done

# Same pooling dimension on the server side, a smaller sample (each
# server_chaos_test.py round already fans multiple concurrent TCP flows
# into every "real" client, so pooling's effect shows up even with fewer
# condition pairings than the client side needed).
SERVER_POOL_COMBOS="clean:3:1 quic_bad:1:2 combo_all_bad:3:2"
for combo in $SERVER_POOL_COMBOS; do
  cond="${combo%%:*}"
  rest="${combo#*:}"
  cpu="${rest%%:*}"
  us="${rest##*:}"
  desc="--condition=$cond --conn-per-udp=$cpu --udp-socket=$us"
  echo "=== server_chaos_test.py $desc ===" | tee -a "$RESULTS"
  python3 -u server_chaos_test.py --condition="$cond" --conn-per-udp="$cpu" \
      --udp-socket="$us" >> "$RESULTS" 2>&1
  echo "exit=$? for server_chaos_test.py $desc" | tee -a "$RESULTS"
done

# Deterministic reentrancy regression, targeted (not incidental like the
# chaos suites above) at the exact crashes fixed in 715a5f926: concurrent
# TCP bursts through quictun_client while quictun_server gets killed mid-
# burst, repeatedly -- see pool_reentrancy_test.py's own top comment.
# conn_per_udp=1 is the widest cross-tunnel window (every tunnel on one
# connection); the other shapes spread them over more connections and
# more sockets.
for shape in 1:1 3:1 1:2; do
  cpu="${shape%%:*}"
  us="${shape##*:}"
  desc="--conn-per-udp=$cpu --udp-socket=$us"
  echo "=== pool_reentrancy_test.py $desc ===" | tee -a "$RESULTS"
  python3 -u pool_reentrancy_test.py --conn-per-udp="$cpu" --udp-socket="$us" \
      >> "$RESULTS" 2>&1
  echo "exit=$? for pool_reentrancy_test.py $desc" | tee -a "$RESULTS"
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

# Does pooling actually pool -- many concurrent TCP flows really sharing
# at most --udp_socket x --conn_per_udp underlying connections, and really
# opening exactly --udp_socket sockets, not just "still working" (which
# everything above already covers). No condition variants: this is a
# structural property of pool_slots_' own selection logic, not something
# network chaos changes.
echo "=== pool_cap_test.py ===" | tee -a "$RESULTS"
python3 -u pool_cap_test.py >> "$RESULTS" 2>&1
echo "exit=$? for pool_cap_test.py" | tee -a "$RESULTS"

# Pooling against QUIC's own real, protocol-level
# max_streams-per-connection ceiling (--max_streams_per_connection --
# see its own comment in quictun_flags.h), at several actual configured
# values: streams beyond the cap should queue cleanly and get serviced
# once an earlier one closes and frees credit, not error or wedge the
# connection; and two independent, real (never forced to misbehave)
# client processes against the same server each get their own full
# cap's worth of streams, proving the cap is per-connection, not
# shared/global. A real flag, not a test-only hook -- runs against any
# build, no -DQUICTUN_TEST_BUILD needed.
echo "=== max_streams_test.py ===" | tee -a "$RESULTS"
python3 -u max_streams_test.py >> "$RESULTS" 2>&1
echo "exit=$? for max_streams_test.py" | tee -a "$RESULTS"

# Deterministic write-block fault injection (see writeblock_fault_test.py's
# own top-of-file comment for why this exists as a separate, non-network
# dimension): covers the write-blocked-forever bug fixed by
# RearmOnBlockPacketWriter, on each endpoint independently and together.
# Each run carries a sibling stream on the same connection throughout, so
# RearmOnBlockPacketWriter's recovery is checked to be connection-level and
# not scoped to whichever stream the fault-injection counter landed on.
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

# A connection closing while it is still write blocked -- the blocked-writer
# list holds a raw pointer the connection does not unregister itself. See
# writeblock_close_test.py's own top comment for what it can and cannot show.
echo "=== writeblock_close_test.py ===" | tee -a "$RESULTS"
python3 -u writeblock_close_test.py >> "$RESULTS" 2>&1
echo "exit=$? for writeblock_close_test.py" | tee -a "$RESULTS"

# A TCP socket sitting registered with nothing armed when its peer RSTs:
# poll(2) reports POLLHUP regardless of the requested events, and the event
# loop can neither map nor clear it. Asserts on server CPU, since the loop
# keeps servicing events perfectly well while spinning.
echo "=== pollhup_spin_test.py ===" | tee -a "$RESULTS"
python3 -u pollhup_spin_test.py >> "$RESULTS" 2>&1
echo "exit=$? for pollhup_spin_test.py" | tee -a "$RESULTS"

# --target refusing the TCP connect (ECONNREFUSED) -- another coverage gap
# (QuictunServerConnection::ConnectComplete()'s failure branch), matching
# the ordinary operational case of the backend service being down.
echo "=== target_unreachable_test.py ===" | tee -a "$RESULTS"
python3 -u target_unreachable_test.py >> "$RESULTS" 2>&1
echo "exit=$? for target_unreachable_test.py" | tee -a "$RESULTS"

# Same, but reusing one client: does one stream's dial failure wedge or
# crash the connection for the next stream assigned to it? The run above
# can't exercise this -- every attempt there gets its own fresh client.
echo "=== target_unreachable_test.py --reuse-client ===" | tee -a "$RESULTS"
python3 -u target_unreachable_test.py --reuse-client >> "$RESULTS" 2>&1
echo "exit=$? for target_unreachable_test.py --reuse-client" | tee -a "$RESULTS"

# IPv6 dual-stack --listen ([::]) reached by an IPv4 peer -- every other
# test's --listen is plain IPv4.
echo "=== dualstack_ipv6_test.py ===" | tee -a "$RESULTS"
python3 -u dualstack_ipv6_test.py >> "$RESULTS" 2>&1
echo "exit=$? for dualstack_ipv6_test.py" | tee -a "$RESULTS"

echo "=== dualstack_ipv6_test.py --conn-per-udp=2 --udp-socket=2 ===" | tee -a "$RESULTS"
python3 -u dualstack_ipv6_test.py --conn-per-udp=2 --udp-socket=2 >> "$RESULTS" 2>&1
echo "exit=$? for dualstack_ipv6_test.py --conn-per-udp=2 --udp-socket=2" | tee -a "$RESULTS"

echo "=== MATRIX COMPLETE ===" | tee -a "$RESULTS"
echo "Full results: $RESULTS"
