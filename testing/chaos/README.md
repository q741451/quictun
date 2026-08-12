# quictun chaos/regression test suite

Black-box regression tests for `quictun_client`/`quictun_server`: real
built binaries, driven as subprocesses over real sockets on loopback.
Plain Python/bash, not Bazel test targets.

```
bazel build -c opt //quiche:quictun_client //quiche:quictun_server
./run_full_matrix.sh
```

## Suites

| Script | Covers |
| --- | --- |
| `server_chaos_test.py` | Long-running server vs. many chaotic clients, 5 network conditions. |
| `client_chaos_test.py` | Long-running client while the server gets killed/restarted underneath it. |
| `pool_reentrancy_test.py` | `--quic_conn` pooling reentrancy-crash regression. |
| `pool_cap_test.py` | `--quic_conn` actually caps connection count. |
| `pool_soak_test.py` | Sustained-duration fd/RSS leak trend check. |
| `max_streams_test.py` | `--quic_conn` pooling vs. QUIC's own real max_streams-per-connection ceiling. Needs `-DQUICTUN_TEST_BUILD`. |
| `writeblock_fault_test.py` | Fault injection for the write-blocked-forever bug. Needs `-DQUICTUN_TEST_BUILD`. |
| `target_unreachable_test.py` | `--target` refusing the TCP connect. |
| `dualstack_ipv6_test.py` | IPv6 dual-stack `--listen=[::]` reached by an IPv4 peer. |

Each runs standalone -- see its own `--help`/top comment (most also take
`--quic-conn=N` to exercise `--quic_conn` pooling). Shared helpers
(imported/spawned, not run directly): `chaos_actor.py`, `chaos_monitor.py`,
`chaos_target.py`, `netchaos_relay.py`.

## Running everything

```
./run_full_matrix.sh
```

Results go to `$MATRIX_RESULTS` (default
`/tmp/quictun_matrix_results.txt`), tee'd to stdout.

`writeblock_fault_test.py` needs the binaries built with
`-DQUICTUN_TEST_BUILD`, or it silently no-ops:

```
bazel build -c opt --copt=-DQUICTUN_TEST_BUILD \
    //quiche:quictun_client //quiche:quictun_server
```

Not set by CI or any other normal build.

## Coverage

```
bazel build -c fastbuild \
    --copt=-fprofile-instr-generate --copt=-fcoverage-mapping --copt=-fprofile-continuous \
    --copt=-DQUICTUN_COVERAGE_BUILD --copt=-DQUICTUN_TEST_BUILD \
    --linkopt=-fprofile-instr-generate --linkopt=-fprofile-continuous \
    //quiche:quictun_client //quiche:quictun_server
COVERAGE_DIR=/tmp/quictun_coverage ./run_full_matrix.sh
llvm-profdata merge -sparse /tmp/quictun_coverage/*.profraw -o merged.profdata
llvm-cov report bazel-bin/quiche/quictun_client -object=bazel-bin/quiche/quictun_server -instr-profile=merged.profdata
```

`-c fastbuild`, not `-c opt`: `-c opt` defines `NDEBUG`, which
downgrades `QUIC_BUG`/`QUICHE_BUG` checks to non-fatal logs, masking
real invariant violations. This can occasionally hit an unrelated
pre-existing upstream QUICHE assertion under `-c fastbuild` -- not a
quictun regression, and not something the shipped `-c opt` build hits.

## Before pushing

Run the full matrix, confirm everything passes.
