#!/usr/bin/env python3
"""Coverage-gap test: does connection pooling actually pool?

Every other chaos test that exercises pooling checks that things
still *work* under pooling (echo correctness, no crash, fd/rss stay
bounded) -- none of them ever asserted the feature's own core promise:
that many concurrent TCP tunnels through a client really do share at most
--udp_socket x --conn_per_udp underlying QUIC connections, not one each.

Counted via the server's own admission control rather than the client's
UDP socket count: since the client multiplexes every QUIC connection
onto one shared UDP socket, /proc/<pid>/fd no longer says anything
about how many connections exist. Instead the server runs with
--max_concurrent_connections set to exactly that product, so "the client
stayed within its cap" is directly observable as "every flow succeeded
and the server dropped nothing". A control run one connection below that
product must get dropped, proving the capped results are pooling and not
flows simply failing to overlap.

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


def run_case(udp_socket, conn_per_udp, n_flows, server_cap, log_dir):
    tag = f"u{udp_socket}c{conn_per_udp}"
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
         f"--udp_socket={udp_socket}", f"--conn_per_udp={conn_per_udp}"],
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
    return {"udp_socket": udp_socket, "conn_per_udp": conn_per_udp,
            "n_flows": n_flows,
            "server_cap": server_cap, "drops": drops, "echo_ok": echo_ok,
            "client_rss_ok": client_rss_ok, "server_rss_ok": server_rss_ok}


def main():
    log_dir = "/tmp/quictun_pool_cap_logs"
    os.makedirs(log_dir, exist_ok=True)

    n_flows = 9
    cases = []
    # The server admits exactly --udp_socket x --conn_per_udp connections,
    # so n_flows well above that can only all succeed if the client really
    # pooled. Both dimensions varied: a client that ignored --udp_socket,
    # or that opened a socket's worth of connections per socket, would
    # exceed the cap in one of these.
    for udp_socket, conn_per_udp in ((1, 1), (1, 2), (2, 1), (2, 2)):
        cases.append(run_case(udp_socket, conn_per_udp, n_flows,
                              udp_socket * conn_per_udp, log_dir))
    # Control: the same shape one connection short. Some flows must be
    # turned away, proving the capped results above are pooling actually
    # happening and not flows finishing too fast to ever overlap.
    cases.append(run_case(2, 2, n_flows, 3, log_dir))

    print("=== SUMMARY ===")
    ok = True
    for c in cases:
        if c is None:
            ok = False
            continue
        shape = f"udp_socket={c['udp_socket']} conn_per_udp={c['conn_per_udp']}"
        drops, echo_ok = c["drops"], c["echo_ok"]
        capped = c["server_cap"] < c["udp_socket"] * c["conn_per_udp"]
        if not (c["client_rss_ok"] and c["server_rss_ok"]):
            print(f"  {shape}: FAIL -- rss growth over threshold "
                  f"(client_rss_ok={c['client_rss_ok']} server_rss_ok={c['server_rss_ok']})")
            ok = False
            continue
        if capped:
            good = drops > 0 and echo_ok < c["n_flows"]
            print(f"  {shape} (control, server cap {c['server_cap']}): drops={drops} "
                  f"echo_ok={echo_ok}/{c['n_flows']}, expected drops>0 and "
                  f"echo_ok<{c['n_flows']} -- {'PASS' if good else 'FAIL'}")
        else:
            good = drops == 0 and echo_ok == c["n_flows"]
            print(f"  {shape}: drops={drops} echo_ok={echo_ok}/{c['n_flows']}, "
                  f"expected drops=0 and all echoes ok under server cap {c['server_cap']} -- "
                  f"{'PASS' if good else 'FAIL'}")
        ok = ok and good

    print(f"=== pool_cap_test VERDICT: {'PASS' if ok else 'FAIL'} ===", flush=True)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
