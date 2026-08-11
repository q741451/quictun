#!/usr/bin/env python3
"""Formalizes the ad-hoc repro that found and verified all three
reentrancy crashes fixed in 715a5f926: QuictunClientConnection::
StartTunnel()'s closed_ check, QuictunClientConnection::Close()/
QuictunServerConnection::Close()'s snapshot-then-iterate pattern, and
QuictunTunnel's started_ guard.

Fires concurrent bursts of short-lived TCP connections through
quictun_client while repeatedly killing and restarting quictun_server
mid-burst -- the exact trigger (a UDP write failing, or an incoming
packet closing the whole connection, while other tunnels on the same
connection are still mid-callback) that a real gdb backtrace confirmed
each crash from.

Runs under a configurable --quic-conn. At --quic-conn=0 every TCP gets
its own one-tunnel-per-connection QUIC connection -- the reentrancy
StartTunnel()'s bug needed can still happen there (it's been present
since the very first commit), but a tunnel's own Close() can never race
a *sibling* tunnel's in-flight callback, since there is no sibling.
--quic-conn>0 is what makes multiple tunnels genuinely share one
connection, maximizing exactly the cross-tunnel reentrancy window
QuictunClientConnection::Close()/QuictunServerConnection::Close()'s
snapshot fix and QuictunTunnel's started_ guard exist for -- run at a
few different pool sizes (1 and a larger one) for that reason, not just
the unpooled control.

Usage: python3 pool_reentrancy_test.py --quic-conn=0|1|3
"""
import argparse
import os
import socket
import subprocess
import sys
import threading
import time
import uuid

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
SERVER_BIN = f"{REPO}/bazel-bin/quiche/quictun_server"
CLIENT_BIN = f"{REPO}/bazel-bin/quiche/quictun_client"
TARGET = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chaos_target.py")

KEY = "pool-reentrancy-key"
BASE_PORT = 29200


def alloc_ports(n):
    global BASE_PORT
    ports = list(range(BASE_PORT, BASE_PORT + n))
    BASE_PORT += n
    return ports


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


def short_echo(port, results, idx):
    # A distinct, per-call random payload -- not a fixed literal -- and a
    # strict equality check on the echo: this is a multiplexing test, so a
    # bug that crossed two concurrent tunnels' data (stream id mixed up
    # somewhere in the delegate/StreamTcp plumbing) needs to be
    # *detectable* here. Identical fixed payloads across all N concurrent
    # calls in a burst couldn't tell tunnel A receiving tunnel B's echo
    # apart from tunnel A receiving its own -- both would just look like
    # "some bytes came back", which is all the original version of this
    # function checked.
    payload = uuid.uuid4().bytes + os.urandom(32)
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=2)
        s.sendall(payload)
        got = b""
        while len(got) < len(payload):
            chunk = s.recv(4096)
            if not chunk:
                break
            got += chunk
        s.close()
        results[idx] = (got == payload)
    except Exception:
        results[idx] = False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quic-conn", type=int, default=1)
    ap.add_argument("--rounds", type=int, default=8)
    ap.add_argument("--bursts-per-round", type=int, default=25)
    ap.add_argument("--log-dir", default="/tmp/quictun_pool_reentrancy_logs")
    args = ap.parse_args()

    os.makedirs(args.log_dir, exist_ok=True)
    tag = f"qc{args.quic_conn}"

    target_port, server_port, client_local_port = alloc_ports(3)

    target_proc = start_proc(["python3", TARGET, str(target_port)],
                              f"{args.log_dir}/{tag}_target.log")
    time.sleep(0.5)

    def start_server():
        return start_proc(
            [SERVER_BIN, f"--listen=127.0.0.1:{server_port}",
             f"--target=127.0.0.1:{target_port}", f"--key={KEY}",
             "--idle_timeout_seconds=6"],
            f"{args.log_dir}/{tag}_server.log")

    server_proc = start_server()
    time.sleep(1.0)

    client_proc = start_proc(
        [CLIENT_BIN, f"--local=127.0.0.1:{client_local_port}",
         f"--remote=127.0.0.1:{server_port}", f"--key={KEY}",
         "--idle_timeout_seconds=6", f"--quic_conn={args.quic_conn}"],
        f"{args.log_dir}/{tag}_client.log")
    time.sleep(1.0)
    if client_proc.poll() is not None:
        print(f"!!! client exited immediately (quic_conn={args.quic_conn})")
        sys.exit(1)

    wait_tcp_ready("127.0.0.1", client_local_port)

    results = [None] * 10
    threads = [threading.Thread(target=short_echo, args=(client_local_port, results, i))
               for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=3)
    initial_ok = sum(1 for r in results if r)
    print(f"=== [{tag}] initial echoes ok: {initial_ok}/10 ===", flush=True)

    # The actual reentrancy trigger: fire a burst of concurrent short-lived
    # TCP connections (each opening its own tunnel -- sharing the one
    # pooled QUIC connection under --quic-conn>0), then kill the server
    # WHILE they're still in flight. The UDP-write-failure / stream-reset
    # storm this produces is exactly what made one tunnel's Close()
    # reenter while a sibling tunnel on the same connection was still
    # mid-callback in the real crashes this formalizes.
    for round_i in range(args.rounds):
        n = args.bursts_per_round
        burst_results = [None] * n
        threads = [threading.Thread(target=short_echo, args=(client_local_port, burst_results, i))
                   for i in range(n)]
        for t in threads:
            t.start()
        server_proc.kill()
        server_proc.wait()
        for t in threads:
            t.join(timeout=3)
        time.sleep(0.3)
        server_proc = start_server()
        time.sleep(0.5)
        alive = client_proc.poll() is None
        print(f"=== [{tag}] round {round_i+1}/{args.rounds}: client_alive={alive} ===",
              flush=True)
        if not alive:
            print(f"!!! CLIENT DIED during round {round_i+1}, "
                  f"exit code={client_proc.returncode}")
            break

    time.sleep(2.0)
    final_alive = client_proc.poll() is None

    # Sanity: a brand-new echo against the now-stable, freshly-restarted
    # server, through the SAME client process (and, under pooling, likely
    # the same underlying connection(s)) that just weathered the churn.
    sanity_results = [None]
    if final_alive:
        t = threading.Thread(target=short_echo, args=(client_local_port, sanity_results, 0))
        t.start()
        t.join(timeout=5)
    sanity_ok = bool(sanity_results[0])

    print(f"=== [{tag}] SUMMARY ===")
    print(f"  client_alive={final_alive}")
    print(f"  client_exit_code={client_proc.returncode if not final_alive else None}")
    print(f"  sanity_echo_ok={sanity_ok}")

    for p in [client_proc, server_proc, target_proc]:
        try:
            p.kill()
        except Exception:
            pass

    ok = final_alive and sanity_ok
    print(f"=== [{tag}] VERDICT: {'PASS' if ok else 'FAIL'} ===")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
