#!/usr/bin/env python3
"""Coverage-gap test: does --quic_conn pooling actually pool?

Every other chaos test that exercises --quic_conn checks that things
still *work* under pooling (echo correctness, no crash, fd/rss stay
bounded) -- none of them ever asserted the feature's own core promise:
that N concurrent TCP tunnels through a --quic_conn=N client really do
share at most N underlying QUIC connections, not N connections each.
Confirmed by hand once (see the session that added this file) via
/proc/<pid>/net/udp inode-matching before writing this -- this
formalizes that check as an automated regression instead of a one-off
manual measurement.

Counts the client's own UDP sockets (one per underlying QUIC connection
-- quictun_client_driver.cc creates a dedicated UDP socket per
QuictunClientConnection) via /proc/<pid>/fd + /proc/<pid>/net/udp{,6}
inode matching while a burst of concurrent TCP flows is in flight, and
asserts the count never exceeds --quic_conn. Also runs a --quic_conn=0
control, where the count is expected to reach the full flow count
instead (proving pooling is genuinely off by default, not just "also
happens to look capped").

Usage: python3 pool_cap_test.py
"""
import os
import re
import socket
import subprocess
import sys
import threading
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
SERVER_BIN = f"{REPO}/bazel-bin/quiche/quictun_server"
CLIENT_BIN = f"{REPO}/bazel-bin/quiche/quictun_client"
TARGET = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chaos_target.py")

KEY = "pool-cap-key"
BASE_PORT = 29900


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


def count_udp_sockets(pid):
    """Number of this process's open fds that are UDP sockets -- one per
    underlying QUIC connection for quictun_client specifically (it has no
    other UDP socket use)."""
    try:
        fds = os.listdir(f"/proc/{pid}/fd")
    except Exception:
        return None
    inodes = set()
    for fd in fds:
        try:
            link = os.readlink(f"/proc/{pid}/fd/{fd}")
        except Exception:
            continue
        m = re.match(r"socket:\[(\d+)\]", link)
        if m:
            inodes.add(m.group(1))
    count = 0
    for proc_file in (f"/proc/{pid}/net/udp", f"/proc/{pid}/net/udp6"):
        try:
            lines = open(proc_file).read().splitlines()[1:]
        except Exception:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) > 9 and parts[9] in inodes:
                count += 1
    return count


def held_echo(port, hold_s, results, idx):
    """Connects, echoes, then holds the TCP connection open for hold_s
    before closing -- so a burst of these genuinely overlaps in time
    (each keeping its stream/tunnel alive) rather than finishing too fast
    to ever be concurrent."""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        payload = os.urandom(64)
        s.sendall(payload)
        got = b""
        while len(got) < len(payload):
            chunk = s.recv(4096)
            if not chunk:
                break
            got += chunk
        time.sleep(hold_s)
        s.close()
        results[idx] = (got == payload)
    except Exception:
        results[idx] = False


def run_case(quic_conn, n_flows, log_dir):
    tag = f"qc{quic_conn}"
    target_port, server_port, client_port = alloc_ports(3)

    target_proc = start_proc(["python3", TARGET, str(target_port)],
                              f"{log_dir}/{tag}_target.log")
    time.sleep(0.5)
    server_proc = start_proc(
        [SERVER_BIN, f"--listen=127.0.0.1:{server_port}",
         f"--target=127.0.0.1:{target_port}", f"--key={KEY}"],
        f"{log_dir}/{tag}_server.log")
    time.sleep(1.0)
    client_proc = start_proc(
        [CLIENT_BIN, f"--local=127.0.0.1:{client_port}",
         f"--remote=127.0.0.1:{server_port}", f"--key={KEY}",
         f"--quic_conn={quic_conn}"],
        f"{log_dir}/{tag}_client.log")
    time.sleep(1.0)
    if client_proc.poll() is not None:
        print(f"!!! [{tag}] client exited immediately")
        for p in (server_proc, target_proc):
            p.kill()
        return None

    wait_tcp_ready("127.0.0.1", client_port)

    results = [None] * n_flows
    threads = [threading.Thread(target=held_echo, args=(client_port, 1.5, results, i))
               for i in range(n_flows)]
    for t in threads:
        t.start()

    # Sample UDP socket count a few times while the burst is definitely
    # still overlapping (each flow holds for 1.5s after its own echo).
    time.sleep(0.6)
    samples = []
    for _ in range(4):
        c = count_udp_sockets(client_proc.pid)
        if c is not None:
            samples.append(c)
        time.sleep(0.2)

    for t in threads:
        t.join(timeout=5)
    echo_ok = sum(1 for r in results if r)

    for p in (client_proc, server_proc, target_proc):
        try:
            p.kill()
        except Exception:
            pass

    max_observed = max(samples) if samples else None
    print(f"=== [{tag}] n_flows={n_flows} udp_socket_samples={samples} "
          f"max_observed={max_observed} echo_ok={echo_ok}/{n_flows} ===",
          flush=True)
    return {"quic_conn": quic_conn, "n_flows": n_flows,
            "max_observed": max_observed, "echo_ok": echo_ok}


def main():
    log_dir = "/tmp/quictun_pool_cap_logs"
    os.makedirs(log_dir, exist_ok=True)

    n_flows = 9
    cases = []
    # Pooled: cap must hold -- max concurrently-observed UDP sockets must
    # never exceed quic_conn, even with n_flows well above it.
    for qc in (1, 2, 4):
        cases.append(run_case(qc, n_flows, log_dir))
    # Control: unpooled (quictun's original, unchanged default) -- with
    # nothing capping it, n_flows genuinely-concurrent flows should reach
    # (close to) n_flows distinct connections, proving the capped results
    # above are pooling actually happening, not just "the count happens to
    # be low for some unrelated reason" (e.g. flows finishing too fast to
    # overlap at all).
    cases.append(run_case(0, n_flows, log_dir))

    print("=== SUMMARY ===")
    ok = True
    for c in cases:
        if c is None:
            ok = False
            continue
        qc, max_observed, echo_ok = c["quic_conn"], c["max_observed"], c["echo_ok"]
        if echo_ok < c["n_flows"]:
            print(f"  quic_conn={qc}: FAIL -- only {echo_ok}/{c['n_flows']} echoes ok")
            ok = False
            continue
        if qc == 0:
            # Not capped: expect most/all flows to have genuinely
            # overlapped as distinct connections. Some slack (>= n_flows/2)
            # for scheduling jitter -- the point is "clearly not capped at
            # a small N", not an exact count.
            good = max_observed is not None and max_observed >= c["n_flows"] / 2
            print(f"  quic_conn=0 (control): max_observed={max_observed}, "
                  f"expected >= {c['n_flows']/2:.0f} (uncapped) -- "
                  f"{'PASS' if good else 'FAIL'}")
            ok = ok and good
        else:
            good = max_observed is not None and max_observed <= qc
            print(f"  quic_conn={qc}: max_observed={max_observed}, "
                  f"expected <= {qc} -- {'PASS' if good else 'FAIL'}")
            ok = ok and good

    print(f"=== pool_cap_test VERDICT: {'PASS' if ok else 'FAIL'} ===", flush=True)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
