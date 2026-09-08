#!/usr/bin/env python3
"""--tcp_stalled_timeout_seconds: a tunnel holding buffered data it cannot
hand on gets reaped on a short deadline, while a merely quiet one keeps the
lax --tcp_idle_timeout_seconds.

The two cost different things. A quiet tunnel holds an fd and a stream; a
stalled one holds session flow-control credit and send buffer that every
other tunnel on the same QUIC connection shares, so leaving it for the 24h
default can wedge the whole connection. Both classes are swept from the same
intrusive-list tracker, one list each -- so the control below (a quiet tunnel
surviving the stalled deadline) is as much the point as the reaping is.

Usage: python3 stalled_timeout_test.py
"""
import argparse
import os
import socket
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
SERVER_BIN = f"{REPO}/bazel-bin/quiche/quictun_server"
CLIENT_BIN = f"{REPO}/bazel-bin/quiche/quictun_client"
KEY = "stalled-timeout-key"
TARGET_PORT, SERVER_PORT, CLIENT_PORT = 26980, 26981, 26982

# Each connection opens with a one-byte role. "S" blasts until the peer stops
# draining and stays that way; "Q" says hello once and then goes silent. Both
# record how long they lived, which is the whole measurement.
TARGET_SRC = r'''
import socket, sys, threading, time
port, out = int(sys.argv[1]), sys.argv[2]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(16)
lock = threading.Lock()
def record(line):
    with lock:
        open(out, "a").write(line + "\n")
def handle(c):
    t0 = time.time()
    role = c.recv(1)
    if role == b"S":
        c.setblocking(False)
        block = b"A" * 65536
        while True:
            try:
                c.send(block)
            except BlockingIOError:
                time.sleep(0.05)
            except Exception:
                break
        record("S %.1f" % (time.time() - t0))
    else:
        c.sendall(b"hello")
        try:
            while c.recv(4096):
                pass
        except Exception:
            pass
        record("Q %.1f" % (time.time() - t0))
while True:
    c, _ = s.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
'''


def run_phase(name, stalled_seconds, observe_seconds, log_dir):
    """Brings up a fresh client/server pair, opens one quiet tunnel and one
    stalled tunnel, and returns what the target saw."""
    marks = f"{log_dir}/{name}.marks"
    if os.path.exists(marks):
        os.remove(marks)
    target = subprocess.Popen(
        [sys.executable, "-c", TARGET_SRC, str(TARGET_PORT), marks],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    # Small windows so the QUIC side backs up quickly, which is what makes
    # the server stop reading from --target. Idle timeout well past the
    # observation window, so anything reaped here was reaped as stalled.
    tuning = ["--initial_stream_flow_control_window_kb=64",
              "--initial_session_flow_control_window_kb=64",
              "--tcp_idle_timeout_seconds=3600",
              f"--tcp_stalled_timeout_seconds={stalled_seconds}"]
    server = subprocess.Popen(
        [SERVER_BIN, f"--listen=127.0.0.1:{SERVER_PORT}",
         f"--target=127.0.0.1:{TARGET_PORT}", f"--key={KEY}"] + tuning,
        stdout=subprocess.DEVNULL, stderr=open(f"{log_dir}/{name}-server.log", "w"))
    time.sleep(1.0)
    client = subprocess.Popen(
        [CLIENT_BIN, f"--local=127.0.0.1:{CLIENT_PORT}",
         f"--remote=127.0.0.1:{SERVER_PORT}", f"--key={KEY}"] + tuning,
        stdout=subprocess.DEVNULL, stderr=open(f"{log_dir}/{name}-client.log", "w"))
    time.sleep(2.0)
    if server.poll() is not None or client.poll() is not None:
        print(f"!!! endpoint exited immediately, check {log_dir}")
        sys.exit(1)

    # Quiet one first, and drained on both sides, so nothing is buffered
    # anywhere on its behalf before the stalled one starts hogging.
    quiet = socket.create_connection(("127.0.0.1", CLIENT_PORT), 5)
    quiet.sendall(b"Q")
    quiet.settimeout(10)
    assert quiet.recv(64) == b"hello", "quiet tunnel never came up"
    quiet.settimeout(None)

    stalled = socket.create_connection(("127.0.0.1", CLIENT_PORT), 5)
    stalled.sendall(b"S")  # and never read a byte of the reply

    time.sleep(observe_seconds)
    alive = server.poll() is None and client.poll() is None
    seen = {}
    if os.path.exists(marks):
        for line in open(marks):
            role, elapsed = line.split()
            seen[role] = float(elapsed)
    for s in (quiet, stalled):
        try: s.close()
        except Exception: pass
    for p in (client, server, target):
        try: p.kill()
        except Exception: pass
    time.sleep(0.5)
    return alive, seen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log-dir", default="/tmp/quictun_stalled_logs")
    ap.add_argument("--stalled-seconds", type=int, default=5)
    ap.add_argument("--observe-seconds", type=int, default=25)
    args = ap.parse_args()
    os.makedirs(args.log_dir, exist_ok=True)

    print(f"=== phase 1: --tcp_stalled_timeout_seconds={args.stalled_seconds} ===",
          flush=True)
    alive1, seen1 = run_phase("short", args.stalled_seconds, args.observe_seconds,
                              args.log_dir)
    print(f"    target saw: {seen1}", flush=True)

    # Same scenario with the deadline out past the window: proves phase 1's
    # reaping is attributable to the flag and not to the scenario itself.
    print("=== phase 2 (control): --tcp_stalled_timeout_seconds=3600 ===",
          flush=True)
    alive2, seen2 = run_phase("long", 3600, args.observe_seconds, args.log_dir)
    print(f"    target saw: {seen2}", flush=True)

    reaped = "S" in seen1
    in_window = reaped and args.stalled_seconds <= seen1["S"] <= args.observe_seconds
    quiet_survived = "Q" not in seen1
    control_survived = "S" not in seen2 and "Q" not in seen2

    ok = alive1 and alive2 and reaped and in_window and quiet_survived and control_survived
    print("=== SUMMARY ===")
    print(f"  stalled tunnel reaped={reaped} after={seen1.get('S')}s "
          f"(expect {args.stalled_seconds}..{args.observe_seconds})")
    print(f"  quiet tunnel survived={quiet_survived} (must, idle timeout is 3600)")
    print(f"  control: nothing reaped at 3600={control_survived}")
    print(f"  endpoints alive: phase1={alive1} phase2={alive2}")
    print(f"=== stalled_timeout_test VERDICT: {'PASS' if ok else 'FAIL'} ===",
          flush=True)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
