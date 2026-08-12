#!/usr/bin/env python3
"""Coverage-gap test: --quic_conn pooling against QUIC's own real,
protocol-level max_streams-per-connection ceiling (--max_streams_per_connection,
quictun_flags.h -- see its own comment).

PHASE 1/2 (per --max-streams value tested, see main()): TCP flows beyond
the cap queue cleanly (via pending_tcps_/MaybeOpenStreams()) rather than
erroring or wedging the connection, and get serviced once an earlier
stream closes and frees MAX_STREAMS credit -- exercising the full
server-side OnStreamClosed() -> SendMaxStreamsFrame() -> client-side
MaybeAllowNewOutgoingStreams() -> OnCanCreateNewOutgoingStream() ->
MaybeOpenStreams() chain end to end.

PHASE 3: the cap is genuinely per-*connection*, not shared/global --
two independent, real, well-behaved quictun_client PROCESSES (not one
client forced to misbehave) against the same server each independently
get their own full cap's worth of streams, unaffected by the other
also being maxed out at the same time.

Uses a real flag (not a test-only hook), so this runs against any
build -- no -DQUICTUN_TEST_BUILD requirement.

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
BASE_PORT = 26960


def alloc_ports(n):
    global BASE_PORT
    ports = list(range(BASE_PORT, BASE_PORT + n))
    BASE_PORT += n
    return ports


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

    def __init__(self, idx, port):
        self.idx = idx
        self.port = port
        self.sock = None
        self.got_echo = False
        self.error = None
        self.release_event = threading.Event()
        self.thread = threading.Thread(target=self._run)

    def _run(self):
        try:
            self.sock = socket.create_connection(("127.0.0.1", self.port), timeout=3)
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


def phases_1_and_2(max_streams, log_dir):
    """Single client, single connection: cap enforced, queue recovers."""
    tag = f"max_streams_qc1_cap{max_streams}"
    n_conns = max_streams + 7  # comfortably past the cap either way

    target_port, server_port, client_port = alloc_ports(3)
    target_proc = start_proc(["python3", TARGET, str(target_port)],
                              f"{log_dir}/{tag}_target.log")
    time.sleep(0.5)
    server_proc = start_proc(
        [SERVER_BIN, f"--listen=127.0.0.1:{server_port}",
         f"--target=127.0.0.1:{target_port}", f"--key={KEY}",
         "--idle_timeout_seconds=20",
         f"--max_streams_per_connection={max_streams}"],
        f"{log_dir}/{tag}_server.log")
    time.sleep(1.0)
    if server_proc.poll() is not None:
        print(f"!!! [{tag}] server exited immediately")
        return False
    client_proc = start_proc(
        [CLIENT_BIN, f"--local=127.0.0.1:{client_port}",
         f"--remote=127.0.0.1:{server_port}", f"--key={KEY}",
         "--idle_timeout_seconds=20", "--quic_conn=1"],
        f"{log_dir}/{tag}_client.log")
    time.sleep(1.0)
    if client_proc.poll() is not None:
        print(f"!!! [{tag}] client exited immediately")
        return False
    wait_tcp_ready("127.0.0.1", client_port)

    print(f"=== [{tag}] opening {n_conns} concurrent held TCP conns through a "
          f"single --quic_conn=1 connection capped at max_streams_per_connection="
          f"{max_streams} ===", flush=True)
    conns = [HeldConn(i, client_port) for i in range(n_conns)]
    for c in conns:
        c.start()
        time.sleep(0.05)
    time.sleep(2.0)

    responded = [c.idx for c in conns if c.got_echo]
    not_responded = [c.idx for c in conns if not c.got_echo and not c.error]
    errored = [(c.idx, c.error) for c in conns if c.error]
    print(f"    responded: {responded}")
    print(f"    not yet responded (expected: queued): {not_responded}")
    print(f"    errored: {errored}")
    client_alive = client_proc.poll() is None
    server_alive = server_proc.poll() is None
    print(f"    client_alive={client_alive} server_alive={server_alive}")

    phase1_ok = (len(responded) == max_streams and
                 len(not_responded) == n_conns - max_streams and
                 not errored and client_alive and server_alive)
    print(f"=== [{tag}] PHASE 1 (cap correctly enforced at {max_streams}): "
          f"{'PASS' if phase1_ok else 'FAIL'} ===", flush=True)

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
    print(f"    newly responded after freeing a slot (waited up to 10s): "
          f"{newly_responded}")

    client_alive2 = client_proc.poll() is None
    server_alive2 = server_proc.poll() is None
    phase2_ok = len(newly_responded) >= 1 and client_alive2 and server_alive2
    print(f"=== [{tag}] PHASE 2 (queued stream recovers once credit frees up): "
          f"{'PASS' if phase2_ok else 'FAIL'} ===", flush=True)

    for c in conns:
        if not c.release_event.is_set():
            c.release()
    time.sleep(1.0)
    final_ok = client_proc.poll() is None and server_proc.poll() is None
    print(f"=== [{tag}] final: alive={final_ok} ===", flush=True)

    for p in (client_proc, server_proc, target_proc):
        try:
            p.kill()
        except Exception:
            pass

    return phase1_ok and phase2_ok and final_ok


def phase_3_multi_client(max_streams, log_dir):
    """Two independent, real, well-behaved client PROCESSES against the
    same server -- proves the cap is enforced per-connection, not shared/
    global: both clients independently get their own full max_streams
    worth of open streams, each unaffected by the other also being maxed
    out. No forced/simulated misbehavior anywhere -- every process here
    is completely ordinary quictun_client, run twice."""
    tag = f"max_streams_multiclient_cap{max_streams}"
    n_conns = max_streams + 4

    target_port, server_port = alloc_ports(2)
    target_proc = start_proc(["python3", TARGET, str(target_port)],
                              f"{log_dir}/{tag}_target.log")
    time.sleep(0.5)
    server_proc = start_proc(
        [SERVER_BIN, f"--listen=127.0.0.1:{server_port}",
         f"--target=127.0.0.1:{target_port}", f"--key={KEY}",
         "--idle_timeout_seconds=20",
         f"--max_streams_per_connection={max_streams}"],
        f"{log_dir}/{tag}_server.log")
    time.sleep(1.0)
    if server_proc.poll() is not None:
        print(f"!!! [{tag}] server exited immediately")
        return False

    client_procs = []
    client_ports = []
    for i in range(2):
        port = alloc_ports(1)[0]
        client_ports.append(port)
        p = start_proc(
            [CLIENT_BIN, f"--local=127.0.0.1:{port}",
             f"--remote=127.0.0.1:{server_port}", f"--key={KEY}",
             "--idle_timeout_seconds=20", "--quic_conn=1"],
            f"{log_dir}/{tag}_client{i}.log")
        client_procs.append(p)
    time.sleep(1.0)
    if any(p.poll() is not None for p in client_procs):
        print(f"!!! [{tag}] a client exited immediately")
        return False
    for port in client_ports:
        wait_tcp_ready("127.0.0.1", port)

    print(f"=== [{tag}] 2 independent client processes, each opening "
          f"{n_conns} conns through its own --quic_conn=1 connection, "
          f"same server capped at max_streams_per_connection={max_streams} ===",
          flush=True)

    all_conns = {}  # client index -> list[HeldConn]
    for ci, port in enumerate(client_ports):
        conns = [HeldConn(i, port) for i in range(n_conns)]
        all_conns[ci] = conns
        for c in conns:
            c.start()
            time.sleep(0.03)
    time.sleep(2.5)

    ok = True
    for ci, conns in all_conns.items():
        responded = [c.idx for c in conns if c.got_echo]
        not_responded = [c.idx for c in conns if not c.got_echo and not c.error]
        errored = [c.idx for c in conns if c.error]
        good = (len(responded) == max_streams and not errored)
        print(f"    client {ci}: responded={len(responded)}/{max_streams} "
              f"(expect exactly {max_streams}), queued={len(not_responded)}, "
              f"errored={errored} -- {'OK' if good else 'BAD'}")
        ok = ok and good

    procs_alive = (server_proc.poll() is None and
                   all(p.poll() is None for p in client_procs))
    print(f"    server_alive={server_proc.poll() is None} "
          f"client_procs_alive={[p.poll() is None for p in client_procs]}")

    for conns in all_conns.values():
        for c in conns:
            c.release()
    time.sleep(0.5)

    for p in [target_proc, server_proc] + client_procs:
        try:
            p.kill()
        except Exception:
            pass

    result = ok and procs_alive
    print(f"=== [{tag}] PHASE 3 (per-connection cap independence across "
          f"{len(client_procs)} client processes): "
          f"{'PASS' if result else 'FAIL'} ===", flush=True)
    return result


def main():
    log_dir = "/tmp/quictun_chaos_logs"
    os.makedirs(log_dir, exist_ok=True)

    # Exercise the flag at more than one actual configured value -- not
    # just a single hardcoded number -- so this is real coverage of
    # --max_streams_per_connection itself working correctly across its
    # range, not just of one arbitrarily-picked test constant.
    results = {}
    for max_streams in (3, 6):
        results[f"phase12_cap{max_streams}"] = phases_1_and_2(max_streams, log_dir)
    for max_streams in (2, 4):
        results[f"phase3_cap{max_streams}"] = phase_3_multi_client(max_streams, log_dir)

    print("=== SUMMARY ===")
    overall_ok = True
    for name, ok in results.items():
        print(f"  {name}: {'PASS' if ok else 'FAIL'}")
        overall_ok = overall_ok and ok
    print(f"=== max_streams_test VERDICT: {'PASS' if overall_ok else 'FAIL'} ===",
          flush=True)
    sys.exit(0 if overall_ok else 1)


if __name__ == "__main__":
    main()
