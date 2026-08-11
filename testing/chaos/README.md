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
| `server_chaos_test.py` | Long-running server vs. many chaotic clients, across 5 network conditions. `--quic-conn=N` (default 0) runs every "real" client pooled. |
| `client_chaos_test.py` | Long-running client while the server gets killed/restarted underneath it. `--quic-conn=N` (default 0) runs the observed + noise clients pooled. |
| `pool_reentrancy_test.py` | Deterministic (not incidental) regression for the three `--quic_conn` pooling reentrancy crashes fixed in `715a5f926`: concurrent TCP bursts through one `quictun_client` while `quictun_server` gets killed mid-burst, repeatedly. `--quic-conn=N` (default 1). Each burst uses a distinct random payload with strict echo verification, so a cross-tunnel data mixup would fail it, not just a crash. |
| `pool_cap_test.py` | Does `--quic_conn` pooling actually pool -- asserts N concurrent TCP flows really share at most N underlying QUIC connections (counted via `/proc/<pid>/net/udp{,6}`), with an unpooled control proving the cap isn't just "flows happened not to overlap". No other test asserts this; everything else only checks pooling still *works*, not that it's actually reducing connection count. |
| `writeblock_fault_test.py` | Deterministic fault injection for the write-blocked-forever bug (`RearmOnBlockPacketWriter`). Needs `-DQUICTUN_TEST_BUILD` (see below) to mean anything. `--quic-conn=N` (default 0) adds a concurrent sibling stream on the same pooled connection, checking the block/rearm recovery is connection-level, not scoped to just the one stream that tripped it. |
| `target_unreachable_test.py` | `--target` refusing the TCP connect. `--quic-conn=N` (default 0) runs all attempts as sequential streams on one pooled connection instead of separate connections, checking one stream's dial failure doesn't wedge/crash the shared connection for the next. |
| `dualstack_ipv6_test.py` | IPv6 dual-stack `--listen=[::]` reached by an IPv4 peer. `--quic-conn=N` (default 0) for basic regression coverage that pooling and address-family remapping don't interact badly. |

Each runs standalone -- see its own `--help`/top comment. Shared
helpers (imported/spawned, not run directly): `chaos_actor.py`,
`chaos_monitor.py`, `chaos_target.py`, `netchaos_relay.py`.

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
