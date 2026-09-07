#!/usr/bin/env python3
"""Coverage-gap test: does --quic_conn pooling actually pool?

Every other chaos test that exercises --quic_conn checks that things
still *work* under pooling (echo correctness, no crash, fd/rss stay
bounded) -- none of them ever asserted the feature's own core promise:
that N concurrent TCP tunnels through a --quic_conn=N client really do
share at most N underlying QUIC connections, not N connections each.

Counted via the server's own admission control rather than the client's
UDP socket count: since the client multiplexes every QUIC connection
onto one shared UDP socket, /proc/<pid>/fd no longer says anything
about how many connections exist. Instead the server runs with
--max_concurrent_connections set to exactly --quic_conn, so "the client
stayed within its cap" is directly observable as "every flow succeeded
and the server dropped nothing". The --quic_conn=0 control uses the
same cap below its flow count and must get dropped, proving the capped
results are pooling and not flows simply failing to overlap.

Usage: python3 pool_cap_test.py
"""
import os
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import chaos_monitor

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


def run_case(quic_conn, n_flows, server_cap, log_dir):
    tag = f"qc{quic_conn}"
    target_port, server_port, client_port = alloc_ports(3)

    target_proc = start_proc(["python3", TARGET, str(target_port)],
                              f"{log_dir}/{tag}_target.log")
    time.sleep(0.5)
    server_proc = start_proc(
        [SERVER_BIN, f"--listen=127.0.0.1:{server_port}",
         f"--target=127.0.0.1:{target_port}", f"--key={KEY}",
         f"--max_concurrent_connections={server_cap}",
         # The drop line is QUIC_LOG(INFO); without this it never prints.
         "--stderrthreshold=0"],
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

    # rss_kb, not just the UDP-socket cap this test otherwise focuses on --
    # fewer connections isn't automatically "no leak"; a per-stream
    # StreamTcp/StreamTarget entry not cleaned up would leak memory even
    # while the connection count itself stayed perfectly capped.
    client_sampler = chaos_monitor.Sampler(client_proc.pid)
    client_sampler.sample()
    client_baseline = client_sampler.summary()
    server_sampler = chaos_monitor.Sampler(server_proc.pid)
    server_sampler.sample()
    server_baseline = server_sampler.summary()

    results = [None] * n_flows
    threads = [threading.Thread(target=held_echo, args=(client_port, 1.5, results, i))
               for i in range(n_flows)]
    for t in threads:
        t.start()

    for t in threads:
        t.join(timeout=10)
    echo_ok = sum(1 for r in results if r)
    drops = open(f"{log_dir}/{tag}_server.log").read().count(
        "Dropping new connection attempt")

    client_sampler.sample()
    client_summary = client_sampler.summary()
    server_sampler.sample()
    server_summary = server_sampler.summary()
    client_rss_ok = (client_summary['rss_kb_last'] is not None and client_baseline['rss_kb_last'] is not None and
                      client_summary['rss_kb_last'] <= client_baseline['rss_kb_last'] + 100000)
    server_rss_ok = (server_summary['rss_kb_last'] is not None and server_baseline['rss_kb_last'] is not None and
                      server_summary['rss_kb_last'] <= server_baseline['rss_kb_last'] + 100000)

    for p in (client_proc, server_proc, target_proc):
        try:
            p.kill()
        except Exception:
            pass

    print(f"=== [{tag}] n_flows={n_flows} server_cap={server_cap} "
          f"drops={drops} echo_ok={echo_ok}/{n_flows} "
          f"client_rss_kb={client_baseline['rss_kb_last']}->{client_summary['rss_kb_last']} "
          f"server_rss_kb={server_baseline['rss_kb_last']}->{server_summary['rss_kb_last']} ===",
          flush=True)
    return {"quic_conn": quic_conn, "n_flows": n_flows,
            "server_cap": server_cap, "drops": drops, "echo_ok": echo_ok,
            "client_rss_ok": client_rss_ok, "server_rss_ok": server_rss_ok}


def main():
    log_dir = "/tmp/quictun_pool_cap_logs"
    os.makedirs(log_dir, exist_ok=True)

    n_flows = 9
    cases = []
    # Pooled: the server admits exactly quic_conn connections, so n_flows
    # well above it can only all succeed if the client really pooled.
    for qc in (1, 2, 4):
        cases.append(run_case(qc, n_flows, qc, log_dir))
    # Control: unpooled (quictun's original, unchanged default) -- one
    # connection per flow, so the same cap must turn some of them away.
    # Proves the capped results above are pooling actually happening, not
    # flows finishing too fast to ever overlap.
    cases.append(run_case(0, n_flows, 4, log_dir))

    print("=== SUMMARY ===")
    ok = True
    for c in cases:
        if c is None:
            ok = False
            continue
        qc, drops, echo_ok = c["quic_conn"], c["drops"], c["echo_ok"]
        if not (c["client_rss_ok"] and c["server_rss_ok"]):
            print(f"  quic_conn={qc}: FAIL -- rss growth over threshold "
                  f"(client_rss_ok={c['client_rss_ok']} server_rss_ok={c['server_rss_ok']})")
            ok = False
            continue
        if qc == 0:
            good = drops > 0 and echo_ok < c["n_flows"]
            print(f"  quic_conn=0 (control): drops={drops} echo_ok={echo_ok}/{c['n_flows']}, "
                  f"expected drops>0 and echo_ok<{c['n_flows']} (uncapped) -- "
                  f"{'PASS' if good else 'FAIL'}")
        else:
            good = drops == 0 and echo_ok == c["n_flows"]
            print(f"  quic_conn={qc}: drops={drops} echo_ok={echo_ok}/{c['n_flows']}, "
                  f"expected drops=0 and all echoes ok under server cap {c['server_cap']} -- "
                  f"{'PASS' if good else 'FAIL'}")
        ok = ok and good

    print(f"=== pool_cap_test VERDICT: {'PASS' if ok else 'FAIL'} ===", flush=True)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
