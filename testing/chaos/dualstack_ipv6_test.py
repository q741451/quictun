#!/usr/bin/env python3
"""Coverage-gap test: quictun_server --listen on an IPv6 dual-stack
wildcard ([::]) receiving connections from an IPv4 peer -- exercises
AdaptPeerAddressForListenSocket() in quictun_server_driver.cc, confirmed
via llvm-cov to have zero coverage from the rest of the suite (every
other test's --listen is a plain IPv4 127.0.0.1 address).

Why this path exists at all (see the function's own comment):
QuicPacketReader normalizes v4-mapped IPv6 peer addresses (e.g.
"::ffff:127.0.0.1") down to plain IPv4 form for its own dispatch
bookkeeping, but quictun's per-connection sockets are always the same
address family as the --listen socket (IPv6, for SO_REUSEADDR/
SO_REUSEPORT migration to work) -- handing a plain-IPv4 sockaddr to
sendmsg() on an AF_INET6 socket is a family mismatch the kernel rejects
with EINVAL, breaking the connection's very first write. Without this
re-mapping, --listen=[::]:PORT (the default -- see quictun_flags.cc)
being reached by any real-world IPv4 client (the overwhelmingly common
case) would be silently broken, not just an untested corner: nothing
about the handshake itself would fail (it's the *response* write that
would EINVAL), so this would likely present as "server never replies to
IPv4 clients" rather than an obvious startup error.

Also connects via real IPv6 (::1) for symmetry/regression coverage of
the non-remapped (already same-family) path.

Usage: python3 dualstack_ipv6_test.py
"""
import argparse
import os
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import chaos_actor

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))  # repo root, two levels up from testing/chaos/
SERVER_BIN = f"{REPO}/bazel-bin/quiche/quictun_server"
CLIENT_BIN = f"{REPO}/bazel-bin/quiche/quictun_client"
TARGET = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chaos_target.py")

KEY = "dualstack-ipv6-key"


def start_proc(cmd, log_path):
    f = open(log_path, "w")
    return subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT)


def wait_tcp_ready(host, port, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection((host, port), timeout=0.3)
            s.close()
            return True
        except Exception:
            time.sleep(0.1)
    return False


def run_one(remote_host, target_port, server_listen_port, local_port,
            log_dir, tag, quic_conn=0):
    print(f"=== [{tag}] starting chaos_target on {target_port} ===", flush=True)
    target_proc = start_proc(["python3", TARGET, str(target_port)],
                              f"{log_dir}/{tag}_target.log")
    time.sleep(0.5)

    print(f"=== [{tag}] starting quictun_server --listen=[::]:"
          f"{server_listen_port} ===", flush=True)
    server_proc = start_proc(
        [SERVER_BIN, f"--listen=[::]:{server_listen_port}",
         f"--target=127.0.0.1:{target_port}", f"--key={KEY}",
         "--idle_timeout_seconds=10"],
        f"{log_dir}/{tag}_server.log")
    time.sleep(1.0)
    if server_proc.poll() is not None:
        print(f"!!! server exited immediately, check {log_dir}/{tag}_server.log")
        return False

    # quic_conn doesn't change anything about the address-family remapping
    # this test targets (AdaptPeerAddressForListenSocket() runs once per
    # new UDP connection, at setup, regardless of how many streams ride on
    # it afterward) -- included anyway for basic regression coverage that
    # pooling and dual-stack remapping don't interact badly (e.g. a pooled
    # connection's *second* stream somehow not inheriting the already-
    # remapped peer address).
    quic_conn_flags = [f"--quic_conn={quic_conn}"] if quic_conn else []
    print(f"=== [{tag}] starting quictun_client --remote={remote_host}:"
          f"{server_listen_port} (quic_conn={quic_conn}) ===", flush=True)
    client_proc = start_proc(
        [CLIENT_BIN, f"--local=127.0.0.1:{local_port}",
         f"--remote={remote_host}:{server_listen_port}", f"--key={KEY}",
         "--idle_timeout_seconds=10"] + quic_conn_flags,
        f"{log_dir}/{tag}_client.log")
    time.sleep(1.0)
    if client_proc.poll() is not None:
        print(f"!!! client exited immediately, check {log_dir}/{tag}_client.log")
        return False

    wait_tcp_ready("127.0.0.1", local_port)
    ok = False
    try:
        ok = chaos_actor.short_echo(("127.0.0.1", local_port), timeout=8)
        # A second, larger exchange -- the first packet in each direction
        # is where a real EINVAL-on-write would show up, but a bigger
        # transfer better matches the real bidirectional pattern.
        ok = ok and chaos_actor.big_download(("127.0.0.1", local_port), 256 * 1024)
        if quic_conn:
            # A second, concurrent stream on the same connection -- proves
            # the remapped peer address (established once, at connection
            # setup) really does carry over correctly to later streams too,
            # not just the first one that happened to trigger the remap.
            ok = ok and chaos_actor.short_echo(("127.0.0.1", local_port), timeout=8)
    except Exception as e:
        print(f"    exception: {e}", flush=True)
    print(f"=== [{tag}] echo+download ok={ok} ===", flush=True)

    for p in (client_proc, server_proc, target_proc):
        if p.poll() is None:
            p.terminate()
    time.sleep(0.3)
    for p in (client_proc, server_proc, target_proc):
        if p.poll() is None:
            p.kill()
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quic-conn", type=int, default=0)
    args = ap.parse_args()

    log_dir = "/tmp/quictun_chaos_logs"
    os.makedirs(log_dir, exist_ok=True)

    # IPv4 peer against the IPv6 dual-stack listener -- the actual gap.
    ok_v4 = run_one("127.0.0.1", 26940, 26941, 26942, log_dir,
                    "dualstack_ipv4_peer", quic_conn=args.quic_conn)
    # IPv6 peer against the same listener -- same-family path, for
    # regression coverage alongside the remapped one.
    ok_v6 = run_one("[::1]", 26950, 26951, 26952, log_dir,
                    "dualstack_ipv6_peer", quic_conn=args.quic_conn)

    verdict = "PASS" if (ok_v4 and ok_v6) else "FAIL"
    print(f"=== dualstack_ipv6_test VERDICT: {verdict} "
          f"(ipv4_peer={ok_v4}, ipv6_peer={ok_v6}, quic_conn={args.quic_conn}) ===",
          flush=True)
    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
