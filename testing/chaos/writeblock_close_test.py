#!/usr/bin/env python3
"""Coverage-gap test: a connection that closes while it is still write
blocked.

The driver's blocked-writer list holds a raw QuicBlockedWriterInterface*
and QuicConnection's destructor does not unregister itself, so a
connection destroyed while still listed leaves a dangling entry for the
next writable event to call OnBlockedWriterCanWrite() on -- the bug this
covers. Nothing else in the suite reaches it: writeblock_fault_test.py
injects a block but never closes the connection under it, and the pool
tests close connections but never while blocked.

Loopback cannot produce a real write block at all (confirmed: 24
concurrent 4 MB downloads through an 8 KB send buffer produced zero),
which is why this drives QUICTUN_INJECT_WRITE_BLOCK_AFTER together with
QUICTUN_INJECT_WRITE_BLOCK_REPEAT -- the repeat budget is what keeps a
connection sitting in the list across many event-loop iterations instead
of the single one a one-shot block lasts, i.e. what a congested uplink
would do. The server is then killed so the client's connection closes,
under the block, and gets destroyed.

What this can and cannot show: a dangling entry is a use-after-free, and
without a sanitizer (the musl target has no ASan runtime built) reading
freed memory need not fault. So a PASS here is "the scenario ran and both
ends stayed healthy", not proof the entry was removed -- the assertion
that actually pins it is in the code (RemoveConnection()). Run repeatedly
when chasing a suspected regression.

Usage: python3 writeblock_close_test.py [--rounds=5]
Requires -DQUICTUN_TEST_BUILD (the injector does not exist otherwise).
"""
import argparse
import os
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import chaos_monitor

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
SERVER_BIN = f"{REPO}/bazel-bin/quiche/quictun_server"
CLIENT_BIN = f"{REPO}/bazel-bin/quiche/quictun_client"
KEY = "writeblock-close-key"
IDLE = 4

TARGET_SRC = r'''
import socket, sys, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(64)
def handle(c):
    try:
        hdr = b""
        while len(hdr) < 4:
            d = c.recv(4 - len(hdr))
            if not d: return
            hdr += d
        n = int.from_bytes(hdr, "big"); sent = 0; block = b"A" * 65536
        while sent < n:
            k = min(65536, n - sent); c.sendall(block[:k]); sent += k
    except Exception:
        pass
    finally:
        try: c.close()
        except Exception: pass
while True:
    c, _ = s.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
'''


def start_proc(cmd, log_path, env=None):
    e = dict(os.environ)
    if env:
        e.update(env)
    return subprocess.Popen(cmd, stdout=open(log_path, "w"),
                            stderr=subprocess.STDOUT, env=e)


def pull(port, n, timeout):
    """One tunnelled download; failures are expected while the server is
    down and are not the signal this test reads."""
    s = None
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout)
        s.settimeout(timeout)
        s.sendall(struct.pack(">I", n))
        got = 0
        while got < n:
            d = s.recv(65536)
            if not d:
                break
            got += len(d)
        return got == n
    except Exception:
        return False
    finally:
        if s is not None:
            try: s.close()
            except Exception: pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--log-dir", default="/tmp/quictun_writeblock_close_logs")
    args = ap.parse_args()
    os.makedirs(args.log_dir, exist_ok=True)

    target_port, server_port, client_port = 26960, 26961, 26962
    target_proc = subprocess.Popen([sys.executable, "-c", TARGET_SRC, str(target_port)],
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
    time.sleep(0.5)

    def start_server():
        return start_proc(
            [SERVER_BIN, f"--listen=127.0.0.1:{server_port}",
             f"--target=127.0.0.1:{target_port}", f"--key={KEY}",
             f"--idle_timeout_seconds={IDLE}"],
            f"{args.log_dir}/server.log")

    server_proc = start_server()
    time.sleep(1.0)
    client_proc = start_proc(
        [CLIENT_BIN, f"--local=127.0.0.1:{client_port}",
         f"--remote=127.0.0.1:{server_port}", f"--key={KEY}",
         f"--idle_timeout_seconds={IDLE}", "--conn_per_udp=1", "--udp_socket=1"],
        f"{args.log_dir}/client.log",
        # Block on nearly every write from here on, so the connection is in
        # the blocked-writer list when the server goes away below.
        env={"QUICTUN_INJECT_WRITE_BLOCK_AFTER": "40",
             "QUICTUN_INJECT_WRITE_BLOCK_REPEAT": "1000000"})
    time.sleep(2.0)
    if client_proc.poll() is not None or server_proc.poll() is not None:
        print(f"!!! endpoint exited immediately, check {args.log_dir}")
        sys.exit(1)

    sampler = chaos_monitor.Sampler(client_proc.pid)
    sampler.sample()
    baseline = sampler.summary()
    print(f"=== baseline: client fds={baseline['fds_last']} "
          f"rss_kb={baseline['rss_kb_last']} ===", flush=True)

    ok = True
    for r in range(args.rounds):
        threads = [threading.Thread(target=pull,
                                    args=(client_port, 2 * 1024 * 1024, 4),
                                    daemon=True) for _ in range(8)]
        for t in threads:
            t.start()
        time.sleep(3.0)          # let the injected block pin the connection
        server_proc.kill()
        server_proc.wait()
        time.sleep(IDLE + 3)     # connection times out, closes, is collected
        alive = client_proc.poll() is None
        sampler.sample()
        print(f"    round {r}: client_alive={alive} "
              f"fds={sampler.history[-1]['fds']} "
              f"rss_kb={sampler.history[-1]['rss_kb']}", flush=True)
        if not alive:
            ok = False
            break
        server_proc = start_server()
        time.sleep(2.0)

    recovered = any(pull(client_port, 64 * 1024, 8) for _ in range(3))
    summary = sampler.summary()
    fds_ok = (summary["fds_last"] is not None and baseline["fds_last"] is not None
              and summary["fds_last"] <= baseline["fds_last"] + 10)
    rss_ok = (summary["rss_kb_last"] is not None and baseline["rss_kb_last"] is not None
              and summary["rss_kb_last"] <= baseline["rss_kb_last"] + 100000)
    print(f"=== SUMMARY ===")
    print(f"  client_alive={client_proc.poll() is None} "
          f"server_alive={server_proc.poll() is None}")
    print(f"  recovered_after_rounds={recovered}")
    print(f"  fds: {baseline['fds_last']} -> {summary['fds_last']} ok={fds_ok}")
    print(f"  rss_kb: {baseline['rss_kb_last']} -> {summary['rss_kb_last']} ok={rss_ok}")
    ok = (ok and client_proc.poll() is None and server_proc.poll() is None
          and recovered and fds_ok and rss_ok)
    print(f"=== writeblock_close_test VERDICT: {'PASS' if ok else 'FAIL'} ===",
          flush=True)

    for p in (client_proc, server_proc, target_proc):
        try: p.kill()
        except Exception: pass
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
