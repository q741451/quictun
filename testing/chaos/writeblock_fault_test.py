#!/usr/bin/env python3
"""Deterministic fault-injection test for RearmOnBlockPacketWriter
(quictun_connection_factory.cc), covering the write-blocked-forever bug.

Why not real network-condition chaos, and why not genuine kernel
backpressure (shrunk --udp_socket_buffer_kb, tc-limited loopback): both were
tried first (see the incident writeup) and neither reliably reproduces a
genuine sendmsg() EWOULDBLOCK in this sandbox -- loopback delivery is
synchronous enough (confirmed via strace: thousands of back-to-back
sendmsg() calls against a 4KB SO_SNDBUF, zero EAGAIN) that the send buffer
essentially never visibly backs up, and rate-limiting loopback via tc
(inside an unshare --net --map-root-user namespace, since this sandbox has
no CAP_NET_ADMIN on the host netns) introduced its own unrelated
connectivity stall instead. A black-box test relying on either would be
flaky at best.

Instead this sets QUICTUN_INJECT_WRITE_BLOCK_AFTER=N in the environment of
the process(es) under test (see FaultInjectingPacketWriter in
quictun_connection_factory.cc): the Nth+1 real WritePacket()-or-Flush()
call on that endpoint's UDP writer synthetically reports
WRITE_STATUS_BLOCKED exactly once, without touching the real socket --
deterministically landing inside a real data transfer (N is picked
comfortably past the handshake's own packet count), then never blocking
again. Mirrors QuicDefaultPacketWriter's real IsWriteBlocked()/
SetWritable() contract exactly, so it exercises the exact same downstream
code QuicConnection would run on a genuine block.

REQUIRES bazel-bin's quictun_client/quictun_server to be built with
-DQUICTUN_TEST_BUILD -- FaultInjectingPacketWriter (and the env var above)
is compiled out entirely otherwise, not just runtime-inert, so a normal
build's binaries would silently PASS this without ever actually injecting
anything. e.g.:
  bazel build -c opt --copt=-DQUICTUN_TEST_BUILD \
      //quiche:quictun_client //quiche:quictun_server
Never set in any normal build, including CI's release artifacts.

Without RearmOnBlockPacketWriter: the very first (harmless, near-universal)
writable event already consumed the socket's one-shot writable
subscription before the injected block ever fires, so nothing re-arms it --
the connection hangs forever. With the fix: RearmOnBlockPacketWriter sees
the injected WRITE_STATUS_BLOCKED and re-arms immediately, the event loop's
very next cycle finds the (always was) genuinely-writable socket, and the
transfer completes normally.

Usage: python3 writeblock_fault_test.py [--side=client|server|both]
                                        [--trigger-after=30]
                                        [--payload-mb=2]
"""
import argparse
import os
import random
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))  # repo root, two levels up from testing/chaos/
SERVER_BIN = f"{REPO}/bazel-bin/quiche/quictun_server"
CLIENT_BIN = f"{REPO}/bazel-bin/quiche/quictun_client"
TARGET = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chaos_target.py")

KEY = "writeblock-fault-key"


def start_proc(cmd, log_path, env=None):
    f = open(log_path, "w")
    return subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, env=env)


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


def echo_transfer(local_addr, n_bytes, timeout):
    """Plain-echo mode (exercises both upload and echo-back directions).
    Returns (ok, elapsed, detail)."""
    payload = os.urandom(n_bytes)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        t0 = time.time()
        s.connect(local_addr)
        s.sendall(payload)
        got = b""
        while len(got) < n_bytes:
            chunk = s.recv(262144)
            if not chunk:
                break
            got += chunk
        elapsed = time.time() - t0
        if len(got) < n_bytes:
            return (False, elapsed,
                    f"HUNG/short: got {len(got)}/{n_bytes} bytes after "
                    f"{elapsed:.1f}s")
        if got != payload:
            return False, elapsed, "DATA MISMATCH"
        return True, elapsed, f"OK: {n_bytes} bytes round-tripped in {elapsed:.1f}s"
    except socket.timeout:
        return False, timeout, f"HUNG: no response within {timeout}s"
    except OSError as e:
        # A stuck writer's connection is often not silent forever in
        # practice -- the *other* endpoint's own idle/blackhole timeout
        # eventually fires (it can still receive from the stuck side, just
        # never hears back), tearing the QUIC connection down and cascading
        # into this TCP socket getting closed/reset. Still a FAIL: a
        # healthy transfer should complete well within `timeout`, not end
        # in a reset.
        return False, time.time() - t0, f"CONNECTION FAILED: {e!r}"
    finally:
        try:
            s.close()
        except Exception:
            pass


def short_echo(local_addr, timeout=8):
    payload = os.urandom(random.randint(64, 512))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect(local_addr)
        s.sendall(payload)
        got = b""
        while len(got) < len(payload):
            chunk = s.recv(65536)
            if not chunk:
                break
            got += chunk
        return got == payload
    finally:
        try:
            s.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--side", choices=["client", "server", "both"], default="both")
    ap.add_argument("--trigger-after", type=int, default=30)
    ap.add_argument("--payload-mb", type=float, default=2.0)
    ap.add_argument("--timeout-s", type=float, default=20.0)
    ap.add_argument("--log-dir", default="/tmp/quictun_chaos_logs")
    # --so_txtime switches the writer under test from QuicDefaultPacketWriter
    # to QuicGsoBatchWriter -- coverage showed the whole GSO/batch path,
    # including RearmOnBlockPacketWriter's Flush()-based block detection
    # (as opposed to WritePacket()-based), was never exercised by any
    # existing test. FaultInjectingPacketWriter's shared WritePacket()/
    # Flush() counter (see quictun_connection_factory.cc) is what lets the
    # same --trigger-after budget land on whichever of the two actually
    # reaches the wire Nth, which in batch mode is usually Flush().
    ap.add_argument("--so-txtime", action="store_true")
    args = ap.parse_args()

    os.makedirs(args.log_dir, exist_ok=True)
    tag = f"writeblock_fault_{args.side}" + ("_sotxtime" if args.so_txtime else "")

    target_port = 26910
    server_listen_port = 26911
    local_port = 26912
    so_txtime_flags = ["--so_txtime=true"] if args.so_txtime else []

    def make_env(inject):
        if not inject:
            return None
        e = dict(os.environ)
        e["QUICTUN_INJECT_WRITE_BLOCK_AFTER"] = str(args.trigger_after)
        return e

    print(f"=== [{tag}] starting chaos_target on {target_port} ===", flush=True)
    target_proc = start_proc(["python3", TARGET, str(target_port)],
                              f"{args.log_dir}/{tag}_target.log")
    time.sleep(0.5)

    inject_server = args.side in ("server", "both")
    inject_client = args.side in ("client", "both")
    print(f"=== [{tag}] starting quictun_server (inject={inject_server}, "
          f"trigger_after={args.trigger_after}) ===", flush=True)
    server_proc = start_proc(
        [SERVER_BIN, f"--listen=127.0.0.1:{server_listen_port}",
         f"--target=127.0.0.1:{target_port}", f"--key={KEY}",
         "--idle_timeout_seconds=20"] + so_txtime_flags,
        f"{args.log_dir}/{tag}_server.log", env=make_env(inject_server))
    time.sleep(1.0)
    if server_proc.poll() is not None:
        print(f"!!! server exited immediately, check {args.log_dir}/{tag}_server.log")
        sys.exit(1)

    print(f"=== [{tag}] starting quictun_client (inject={inject_client}, "
          f"trigger_after={args.trigger_after}) ===", flush=True)
    client_proc = start_proc(
        [CLIENT_BIN, f"--local=127.0.0.1:{local_port}",
         f"--remote=127.0.0.1:{server_listen_port}", f"--key={KEY}",
         "--idle_timeout_seconds=20"] + so_txtime_flags,
        f"{args.log_dir}/{tag}_client.log", env=make_env(inject_client))
    time.sleep(1.0)
    if client_proc.poll() is not None:
        print(f"!!! client exited immediately, check {args.log_dir}/{tag}_client.log")
        sys.exit(1)

    wait_tcp_ready("127.0.0.1", local_port)

    n_bytes = int(args.payload_mb * 1024 * 1024)
    print(f"=== [{tag}] transferring {args.payload_mb}MB (should trip the "
          f"injected block ~{args.trigger_after} packets in; "
          f"timeout={args.timeout_s}s) ===", flush=True)
    ok, elapsed, detail = echo_transfer(("127.0.0.1", local_port), n_bytes,
                                        args.timeout_s)
    print(f"=== [{tag}] transfer result: ok={ok} elapsed={elapsed:.1f}s "
          f"detail={detail} ===", flush=True)

    sanity_ok = False
    if ok:
        try:
            sanity_ok = short_echo(("127.0.0.1", local_port), timeout=8)
        except Exception as e:
            print(f"sanity check exception: {e}", flush=True)
    print(f"=== [{tag}] post-transfer sanity short_echo ok={sanity_ok} ===",
          flush=True)

    for p in (client_proc, server_proc, target_proc):
        if p.poll() is None:
            p.terminate()
    time.sleep(0.5)
    for p in (client_proc, server_proc, target_proc):
        if p.poll() is None:
            p.kill()

    verdict = "PASS" if (ok and sanity_ok) else "FAIL"
    print(f"=== [{tag}] VERDICT: {verdict} ===", flush=True)
    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
