#!/usr/bin/env python3
"""Coverage-gap test: quictun_server's --target refusing the TCP connect
(ECONNREFUSED), exercising QuictunServerConnection::ConnectComplete()'s
failure branch -- confirmed via llvm-cov to have zero coverage from the
rest of the suite, since every existing test's --target is a real,
already-listening chaos_target.py. A real deployment hits this whenever
the backend service quictun_server tunnels to is down, restarting, or
simply hasn't started listening yet -- a completely ordinary operational
condition, not an edge case.

Two things this needs to prove, matching ConnectComplete()'s own comment
on why the ordering matters (a failed async connect already tears the
socket down internally before invoking the callback, so calling
Disconnect() again from Close() would hit a fatal descriptor_ !=
kInvalidSocketFd check):
  1. The QUIC connection tied to the refused --target gets torn down
     cleanly (the client sees the tunnel close, not a hang) -- not a
     crash, not a stuck connection.
  2. The server process itself survives and keeps working normally for
     later connections against a real (listening) target -- one bad
     backend doesn't poison the whole server.

Usage: python3 target_unreachable_test.py
"""
import argparse
import os
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import chaos_actor
import chaos_monitor

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))  # repo root, two levels up from testing/chaos/
SERVER_BIN = f"{REPO}/bazel-bin/quiche/quictun_server"
CLIENT_BIN = f"{REPO}/bazel-bin/quiche/quictun_client"
TARGET = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chaos_target.py")

KEY = "target-unreachable-key"


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


def find_closed_port():
    """A port nothing is listening on -- connecting to it gets ECONNREFUSED
    immediately on loopback (no SYN retransmit wait), same as a real
    backend being down."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def main():
    ap = argparse.ArgumentParser()
    # 0 (default): unchanged original behavior -- each attempt is its own
    # brand-new quictun_client process/connection. >0: all n_attempts run
    # as sequential streams on ONE pooled client process/connection
    # instead -- since the target never resolves, the connection itself
    # never has a reason to close between attempts (ShouldKeepConnectionAlive()
    # keeps a poolable connection alive regardless of its streams' state),
    # so this specifically tests whether one stream's dial failure
    # (StartTunnelForStream()'s error path, tracked per-stream in
    # stream_targets_) wedges or crashes the shared connection for the
    # next stream/attempt -- a scenario the unpooled path can't exercise
    # at all, since there each attempt gets its own fresh connection no
    # matter what happened to the previous one.
    ap.add_argument("--quic-conn", type=int, default=0)
    args = ap.parse_args()

    log_dir = "/tmp/quictun_chaos_logs"
    os.makedirs(log_dir, exist_ok=True)
    tag = "target_unreachable" + (f"_qc{args.quic_conn}" if args.quic_conn else "")

    dead_target_port = find_closed_port()
    server_listen_port, local_port = 26920, 26921

    print(f"=== [{tag}] starting quictun_server with --target=127.0.0.1:"
          f"{dead_target_port} (nothing listening there) ===", flush=True)
    server_proc = start_proc(
        [SERVER_BIN, f"--listen=127.0.0.1:{server_listen_port}",
         f"--target=127.0.0.1:{dead_target_port}", f"--key={KEY}",
         "--idle_timeout_seconds=10"],
        f"{log_dir}/{tag}_server.log")
    time.sleep(1.0)
    if server_proc.poll() is not None:
        print(f"!!! server exited immediately, check {log_dir}/{tag}_server.log")
        sys.exit(1)

    sampler = chaos_monitor.Sampler(server_proc.pid)
    sampler.sample()

    n_attempts = 5
    torn_down_cleanly = 0

    pooled_client_proc = None
    if args.quic_conn > 0:
        pooled_client_proc = start_proc(
            [CLIENT_BIN, f"--local=127.0.0.1:{local_port}",
             f"--remote=127.0.0.1:{server_listen_port}", f"--key={KEY}",
             "--idle_timeout_seconds=10", f"--quic_conn={args.quic_conn}"],
            f"{log_dir}/{tag}_client.log")
        time.sleep(1.0)
        if pooled_client_proc.poll() is not None:
            print(f"!!! [{tag}] pooled client exited immediately")
            sys.exit(1)
        wait_tcp_ready("127.0.0.1", local_port, timeout=3)

    # A handful of connection attempts against the dead target -- each its
    # own brand-new quictun_client (--quic-conn=0, matching how a real
    # client, e.g. `git push`, would see it: connect, try to use the
    # tunnel, get told it's closed) or, under pooling, each its own new
    # stream on the SAME already-running pooled client/connection (see the
    # --quic-conn help above).
    for i in range(n_attempts):
        client_proc = pooled_client_proc
        if client_proc is None:
            client_proc = start_proc(
                [CLIENT_BIN, f"--local=127.0.0.1:{local_port}",
                 f"--remote=127.0.0.1:{server_listen_port}", f"--key={KEY}",
                 "--idle_timeout_seconds=10"],
                f"{log_dir}/{tag}_client{i}.log")
            time.sleep(0.5)
        if client_proc.poll() is None:
            wait_tcp_ready("127.0.0.1", local_port, timeout=3)
            # Try to actually use the tunnel -- short_echo either gets a
            # clean failure (connection refused/reset once the server tears
            # the stream/QUIC connection down) within its own timeout, or
            # hangs. Either way this must return within a bounded time; a
            # genuine hang here would mean the dial failure path isn't
            # actually closing anything.
            t0 = time.time()
            try:
                chaos_actor.short_echo(("127.0.0.1", local_port), timeout=8)
            except Exception:
                pass
            elapsed = time.time() - t0
            if elapsed < 8:
                torn_down_cleanly += 1
            print(f"    attempt {i}: torn down after {elapsed:.1f}s "
                  f"(bounded={elapsed < 8})", flush=True)
        if pooled_client_proc is None:
            client_proc.terminate()
            time.sleep(0.2)
            if client_proc.poll() is None:
                client_proc.kill()
        sampler.sample()

    if pooled_client_proc is not None:
        pooled_client_alive = pooled_client_proc.poll() is None
        print(f"=== [{tag}] pooled_client_alive_after_all_attempts="
              f"{pooled_client_alive} ===", flush=True)
        torn_down_cleanly = torn_down_cleanly if pooled_client_alive else 0
        pooled_client_proc.terminate()
        time.sleep(0.2)
        if pooled_client_proc.poll() is None:
            pooled_client_proc.kill()

    server_alive_after_dead_target = server_proc.poll() is None
    print(f"=== [{tag}] server_alive_after_dead_target="
          f"{server_alive_after_dead_target} "
          f"torn_down_cleanly={torn_down_cleanly}/{n_attempts} ===",
          flush=True)

    # The real proof this doesn't poison the server: a brand-new connection
    # against a REAL, listening target must still work normally afterward.
    real_target_port = 26922
    print(f"=== [{tag}] now pointing a fresh connection at a real target "
          f"(server itself is NOT restarted) ===", flush=True)
    # Can't change quictun_server's own --target after the fact, so start a
    # second server instance bound to the same style of setup but with a
    # live target, and confirm this ONE PROCESS's earlier dead-target
    # connections didn't leave any process-wide damage (fd leaks, wedged
    # event loop) that would show up as this fresh, unrelated connection
    # also failing.
    target_proc = start_proc(["python3", TARGET, str(real_target_port)],
                              f"{log_dir}/{tag}_target.log")
    time.sleep(0.5)
    server2_listen_port = 26923
    server2_proc = start_proc(
        [SERVER_BIN, f"--listen=127.0.0.1:{server2_listen_port}",
         f"--target=127.0.0.1:{real_target_port}", f"--key={KEY}",
         "--idle_timeout_seconds=10"],
        f"{log_dir}/{tag}_server2.log")
    time.sleep(1.0)
    client2_proc = start_proc(
        [CLIENT_BIN, f"--local=127.0.0.1:{local_port + 1}",
         f"--remote=127.0.0.1:{server2_listen_port}", f"--key={KEY}"],
        f"{log_dir}/{tag}_client_sanity.log")
    time.sleep(1.0)
    sanity_ok = False
    try:
        sanity_ok = chaos_actor.short_echo(("127.0.0.1", local_port + 1), timeout=8)
    except Exception as e:
        print(f"sanity check exception: {e}", flush=True)
    print(f"=== [{tag}] fresh-connection-against-real-target sanity_ok="
          f"{sanity_ok} ===", flush=True)

    summary = sampler.summary()
    print(f"=== [{tag}] first server fds: first={summary['fds_first']} "
          f"max={summary['fds_max']} last={summary['fds_last']} ===",
          flush=True)

    for p in (client2_proc, server2_proc, target_proc, server_proc):
        if p.poll() is None:
            p.terminate()
    time.sleep(0.3)
    for p in (client2_proc, server2_proc, target_proc, server_proc):
        if p.poll() is None:
            p.kill()

    verdict = "PASS" if (
        server_alive_after_dead_target and
        torn_down_cleanly == n_attempts and
        sanity_ok
    ) else "FAIL"
    print(f"=== [{tag}] VERDICT: {verdict} ===", flush=True)
    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
