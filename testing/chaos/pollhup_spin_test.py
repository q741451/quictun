#!/usr/bin/env python3
"""Coverage-gap test: a TCP socket that is registered with the event loop
but has nothing armed, whose peer then sends a RST.

poll(2) reports POLLHUP, POLLERR and POLLNVAL whether or not they were
requested. QuicPollEventLoop registers every TCP socket with no events
armed until it actually wants a read or a write (upstream's own pattern --
see EventLoopConnectingClientSocket::Open()), and DispatchIoEvent() masks
away anything the registration did not ask for. GetEventMask() has no
mapping for POLLHUP at all, so for such a socket a RST makes poll() return
immediately with nothing dispatchable, forever: the event loop stops
sleeping and pins a core, with no traffic anywhere.

quictun reaches that state because it stops reading from the TCP side
while the QUIC side has not drained -- correct backpressure, and the thing
upstream's only TCP user (connect_tunnel.cc) never does, since it re-arms
its read unconditionally after every completion.

The scenario below builds exactly that: the client stops reading, so the
server stops reading from --target, so the target socket sits with nothing
armed; then the target RSTs. Server CPU is the assertion.

Usage: python3 pollhup_spin_test.py
"""
import argparse
import os
import socket
import struct
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
SERVER_BIN = f"{REPO}/bazel-bin/quiche/quictun_server"
CLIENT_BIN = f"{REPO}/bazel-bin/quiche/quictun_client"
KEY = "pollhup-spin-key"
TARGET_PORT, SERVER_PORT, CLIENT_PORT = 26970, 26971, 26972

# Accepts one connection, blasts until the peer stops draining (i.e. the
# server has stopped reading), waits for the server to settle with nothing
# armed on that socket, then RSTs.
TARGET_SRC = r'''
import socket, struct, sys, threading, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(16)
def handle(c):
    try:
        c.recv(64)
        c.setblocking(False)
        block = b"A" * 65536
        deadline = time.time() + 12
        while time.time() < deadline:
            try:
                c.send(block)
            except BlockingIOError:
                time.sleep(0.05)
            except Exception:
                break
        time.sleep(3)
        c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        c.close()
    except Exception:
        pass
while True:
    c, _ = s.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
'''


def cpu_ticks(pid):
    fields = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    return int(fields[11]) + int(fields[12])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log-dir", default="/tmp/quictun_pollhup_logs")
    # Well above the observed idle floor, well below a pinned core.
    ap.add_argument("--max-cpu-pct", type=float, default=25.0)
    args = ap.parse_args()
    os.makedirs(args.log_dir, exist_ok=True)

    target = subprocess.Popen([sys.executable, "-c", TARGET_SRC, str(TARGET_PORT)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    # Small windows so the QUIC side backs up quickly, which is what makes
    # the server stop reading from --target.
    flow = ["--initial_stream_flow_control_window_kb=64",
            "--initial_session_flow_control_window_kb=64"]
    server = subprocess.Popen(
        [SERVER_BIN, f"--listen=127.0.0.1:{SERVER_PORT}",
         f"--target=127.0.0.1:{TARGET_PORT}", f"--key={KEY}"] + flow,
        stdout=subprocess.DEVNULL, stderr=open(f"{args.log_dir}/server.log", "w"))
    time.sleep(1.0)
    client = subprocess.Popen(
        [CLIENT_BIN, f"--local=127.0.0.1:{CLIENT_PORT}",
         f"--remote=127.0.0.1:{SERVER_PORT}", f"--key={KEY}"] + flow,
        stdout=subprocess.DEVNULL, stderr=open(f"{args.log_dir}/client.log", "w"))
    time.sleep(2.0)
    if server.poll() is not None or client.poll() is not None:
        print(f"!!! endpoint exited immediately, check {args.log_dir}")
        sys.exit(1)

    held = socket.create_connection(("127.0.0.1", CLIENT_PORT), 5)
    held.sendall(b"go")
    print("=== tunnel open; client stops reading, so the server stops "
          "reading from --target ===", flush=True)

    hz = os.sysconf("SC_CLK_TCK")
    samples = []
    prev, t0 = cpu_ticks(server.pid), time.time()
    for i in range(12):
        time.sleep(3.0)
        now, t1 = cpu_ticks(server.pid), time.time()
        pct = (now - prev) / hz / (t1 - t0) * 100
        prev, t0 = now, t1
        samples.append(pct)
        print(f"    t={3 * (i + 1):3d}s  server cpu={pct:5.1f}%", flush=True)

    # The RST lands ~15s in; everything after it is what matters.
    after_rst = samples[6:]
    worst = max(after_rst)
    alive = server.poll() is None and client.poll() is None
    held.close()

    # A fresh tunnel must still work -- a spinning loop still services
    # events, so liveness alone would not catch this.
    time.sleep(1.0)
    recovered = False
    try:
        s2 = socket.create_connection(("127.0.0.1", CLIENT_PORT), 8)
        s2.settimeout(8)
        s2.sendall(b"hi")
        recovered = len(s2.recv(4096)) > 0
        s2.close()
    except Exception as e:
        print(f"    fresh tunnel failed: {e!r}")

    ok = alive and worst <= args.max_cpu_pct and recovered
    print("=== SUMMARY ===")
    print(f"  server cpu after RST: {['%.1f' % p for p in after_rst]}")
    print(f"  worst={worst:.1f}% (expect <= {args.max_cpu_pct})")
    print(f"  both_alive={alive} fresh_tunnel_ok={recovered}")
    print(f"=== pollhup_spin_test VERDICT: {'PASS' if ok else 'FAIL'} ===",
          flush=True)
    for p in (client, server, target):
        try: p.kill()
        except Exception: pass
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
