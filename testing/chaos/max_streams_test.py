#!/usr/bin/env python3
"""Coverage-gap test: --quic_conn pooling against QUIC's own real,
protocol-level max_streams-per-connection ceiling (quictun never touches
this -- see QUICTUN_TEST_MAX_STREAMS's own comment in
quictun_server_driver.cc). Verifies TCP flows beyond the cap queue
cleanly (via pending_tcps_/MaybeOpenStreams()) rather than erroring or
wedging the connection, and get serviced once an earlier stream closes
and frees MAX_STREAMS credit -- exercising the full server-side
OnStreamClosed() -> SendMaxStreamsFrame() -> client-side
MaybeAllowNewOutgoingStreams() -> OnCanCreateNewOutgoingStream() ->
MaybeOpenStreams() chain end to end.

REQUIRES bazel-bin's quictun_client/quictun_server to be built with
-DQUICTUN_TEST_BUILD -- QUICTUN_TEST_MAX_STREAMS is compiled out entirely
otherwise (not just runtime-inert), so a normal build's server would
silently use the real 100-stream default and this test would just never
hit the cap it's trying to exercise.

Usage: python3 max_streams_test.py
"""
import os
import socket
import subprocess
import sys
import threading
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
SERVER_BIN = f"{REPO}/bazel-bin/quiche/quictun_server"
CLIENT_BIN = f"{REPO}/bazel-bin/quiche/quictun_client"
TARGET = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chaos_target.py")

KEY = "max-streams-key"
MAX_STREAMS = 5
N_CONNS = 12  # well past the cap

target_port, server_port, client_port = 26960, 26961, 26962


def start_proc(cmd, log_path, env=None):
    f = open(log_path, "w")
    e = dict(os.environ)
    if env:
        e.update(env)
    return subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, env=e)


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


class HeldConn:
    """Connects, sends a marker payload, and polls for the echo back --
    proving the stream is actually open and servicing data, not just
    TCP-connected client-side (a queued-but-not-yet-opened stream's TCP
    accept() already succeeded locally, well before any QUIC stream
    exists for it) -- then holds the connection open until told to
    release. Polls with a long overall deadline rather than one
    short-timeout attempt: a queued connection has no way to know how
    long it'll wait for a stream slot, and a single early timeout would
    only prove "didn't get serviced immediately", not "never got
    serviced at all" -- confirmed via a real repro to matter: an earlier,
    single-attempt version of this same check mistook a genuinely-working
    ~0.5s recovery for a permanent stall, simply because it had already
    given up on recv() well before the stream ever opened."""

    def __init__(self, idx):
        self.idx = idx
        self.sock = None
        self.got_echo = False
        self.error = None
        self.release_event = threading.Event()
        self.thread = threading.Thread(target=self._run)

    def _run(self):
        try:
            self.sock = socket.create_connection(("127.0.0.1", client_port), timeout=3)
            payload = f"marker-{self.idx}\n".encode()
            self.sock.sendall(payload)
            self.sock.settimeout(0.5)
            deadline = time.time() + 30.0
            while time.time() < deadline and not self.got_echo:
                try:
                    data = self.sock.recv(64)
                    self.got_echo = bool(data)
                except socket.timeout:
                    continue
                except Exception:
                    break
        except Exception as e:
            self.error = str(e)
        self.release_event.wait()
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass

    def start(self):
        self.thread.start()

    def release(self):
        self.release_event.set()
        self.thread.join(timeout=3)


def main():
    log_dir = "/tmp/quictun_chaos_logs"
    os.makedirs(log_dir, exist_ok=True)
    tag = "max_streams"

    target_proc = start_proc(["python3", TARGET, str(target_port)],
                              f"{log_dir}/{tag}_target.log")
    time.sleep(0.5)

    server_proc = start_proc(
        [SERVER_BIN, f"--listen=127.0.0.1:{server_port}",
         f"--target=127.0.0.1:{target_port}", f"--key={KEY}",
         "--idle_timeout_seconds=20"],
        f"{log_dir}/{tag}_server.log", env={"QUICTUN_TEST_MAX_STREAMS": str(MAX_STREAMS)})
    time.sleep(1.0)
    if server_proc.poll() is not None:
        print(f"!!! [{tag}] server exited immediately")
        sys.exit(1)

    client_proc = start_proc(
        [CLIENT_BIN, f"--local=127.0.0.1:{client_port}",
         f"--remote=127.0.0.1:{server_port}", f"--key={KEY}",
         "--idle_timeout_seconds=20", "--quic_conn=1"],
        f"{log_dir}/{tag}_client.log")
    time.sleep(1.0)
    if client_proc.poll() is not None:
        print(f"!!! [{tag}] client exited immediately")
        sys.exit(1)

    wait_tcp_ready("127.0.0.1", client_port)

    print(f"=== [{tag}] opening {N_CONNS} concurrent held TCP conns through a "
          f"single --quic_conn=1 connection capped at MAX_STREAMS={MAX_STREAMS} ===",
          flush=True)

    conns = [HeldConn(i) for i in range(N_CONNS)]
    for c in conns:
        c.start()
        time.sleep(0.05)  # stagger slightly so ordering is deterministic

    time.sleep(2.0)  # let everything that's going to respond immediately, respond

    responded = [c.idx for c in conns if c.got_echo]
    not_responded = [c.idx for c in conns if not c.got_echo and not c.error]
    errored = [(c.idx, c.error) for c in conns if c.error]
    print(f"    responded (streams actually opened): {responded}")
    print(f"    not yet responded (expected: queued in pending_tcps_): {not_responded}")
    print(f"    errored: {errored}")

    client_alive = client_proc.poll() is None
    server_alive = server_proc.poll() is None
    print(f"    client_alive={client_alive} server_alive={server_alive}")

    phase1_ok = (len(responded) == MAX_STREAMS and
                 len(not_responded) == N_CONNS - MAX_STREAMS and
                 not errored and client_alive and server_alive)
    print(f"=== [{tag}] PHASE 1 (cap correctly enforced): "
          f"{'PASS' if phase1_ok else 'FAIL'} ===", flush=True)

    # Free up one stream's worth of credit -- release ONE of the responded
    # (currently-open) connections, then check whether one of the
    # previously-queued ones gets serviced once MAX_STREAMS credit arrives.
    print(f"=== [{tag}] releasing one active connection to free a stream slot ===",
          flush=True)
    if responded:
        conns[responded[0]].release()

    t0 = time.time()
    newly_responded = []
    while time.time() - t0 < 10.0:
        newly_responded = [c.idx for c in conns
                           if c.idx in not_responded and c.got_echo]
        if newly_responded:
            print(f"    t={time.time()-t0:.1f}s: newly responded: {newly_responded}",
                  flush=True)
            break
        time.sleep(0.2)
    still_waiting = [c.idx for c in conns
                     if c.idx in not_responded and not c.got_echo]
    print(f"    newly responded after freeing a slot (waited up to 10s): "
          f"{newly_responded}")
    print(f"    still waiting: {still_waiting}")

    client_alive2 = client_proc.poll() is None
    server_alive2 = server_proc.poll() is None
    print(f"    client_alive={client_alive2} server_alive={server_alive2}")

    phase2_ok = len(newly_responded) >= 1 and client_alive2 and server_alive2
    print(f"=== [{tag}] PHASE 2 (queued stream recovers once credit frees up): "
          f"{'PASS' if phase2_ok else 'FAIL'} ===", flush=True)

    # Cleanup: release everything, confirm no crash on teardown either.
    for c in conns:
        if not c.release_event.is_set():
            c.release()
    time.sleep(1.0)
    final_client_alive = client_proc.poll() is None
    final_server_alive = server_proc.poll() is None
    print(f"=== [{tag}] final: client_alive={final_client_alive} "
          f"server_alive={final_server_alive} ===", flush=True)

    for p in (client_proc, server_proc, target_proc):
        try:
            p.kill()
        except Exception:
            pass

    overall_ok = phase1_ok and phase2_ok and final_client_alive and final_server_alive
    print(f"=== [{tag}] VERDICT: {'PASS' if overall_ok else 'FAIL'} ===", flush=True)
    sys.exit(0 if overall_ok else 1)


if __name__ == "__main__":
    main()
