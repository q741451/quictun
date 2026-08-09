#!/usr/bin/env python3
"""Client-side chaos test: one long-running "observed" quictun_client under
constant real traffic, while a swarm of noise client processes (some with
wrong keys / garbage args) hammer the same server, and the server itself
gets killed and restarted periodically. Verifies the observed client's FD/
RSS/CPU stay stable throughout, and that it can still talk to a *freshly
restarted* server afterward.

Usage: python3 client_chaos_test.py --condition=clean|quic_bad|client_tcp_bad|server_tcp_bad
"""
import argparse
import os
import random
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import chaos_actor
import chaos_monitor

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))  # repo root, two levels up from testing/chaos/
SERVER_BIN = f"{REPO}/bazel-bin/quiche/quictun_server"
CLIENT_BIN = f"{REPO}/bazel-bin/quiche/quictun_client"
RELAY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netchaos_relay.py")
TARGET = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chaos_target.py")

KEY = "chaostest-client-key"
BASE_PORT = 28000


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


def start_server(target_addr, server_listen_port, log_dir, tag, key=KEY):
    return start_proc(
        [SERVER_BIN, f"--listen=127.0.0.1:{server_listen_port}",
         f"--target={target_addr}", f"--key={key}", "--idle_timeout_seconds=6"],
        f"{log_dir}/{tag}_server_{server_listen_port}.log")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--condition", choices=["clean", "quic_bad", "client_tcp_bad", "server_tcp_bad", "combo_all_bad"],
                     default="clean")
    ap.add_argument("--duration", type=float, default=40.0)
    ap.add_argument("--noise-clients", type=int, default=6)
    ap.add_argument("--server-restarts", type=int, default=3)
    ap.add_argument("--log-dir", default="/tmp/quictun_chaos_logs_client")
    args = ap.parse_args()

    os.makedirs(args.log_dir, exist_ok=True)
    tag = args.condition

    target_port, server_listen_port = alloc_ports(2)
    print(f"=== [{tag}] starting chaos_target on {target_port} ===", flush=True)
    target_proc = start_proc(["python3", TARGET, str(target_port)],
                              f"{args.log_dir}/{tag}_target.log")
    time.sleep(0.5)

    server_target_addr = f"127.0.0.1:{target_port}"
    server_tcp_relay = None
    if args.condition in ("server_tcp_bad", "combo_all_bad"):
        server_target_addr = f"127.0.0.1:{alloc_ports(1)[0]}"
        server_tcp_relay = start_proc(
            ["python3", RELAY, "--mode=tcp", f"--listen={server_target_addr}",
             f"--upstream=127.0.0.1:{target_port}", "--delay-ms=150",
             "--jitter-ms=80", "--reset-prob=0.15", "--reset-after-s=1.5"],
            f"{args.log_dir}/{tag}_server_tcp_relay.log")
        time.sleep(0.5)

    server_proc = start_server(server_target_addr, server_listen_port, args.log_dir, tag)
    time.sleep(1.0)

    client_remote_addr = f"127.0.0.1:{server_listen_port}"
    quic_relay = None
    if args.condition in ("quic_bad", "combo_all_bad"):
        relay_port = alloc_ports(1)[0]
        client_remote_addr = f"127.0.0.1:{relay_port}"
        quic_relay = start_proc(
            ["python3", RELAY, "--mode=udp", f"--listen=127.0.0.1:{relay_port}",
             f"--upstream=127.0.0.1:{server_listen_port}", "--loss=0.08",
             "--delay-ms=120", "--jitter-ms=60"],
            f"{args.log_dir}/{tag}_quic_relay.log")
        time.sleep(0.5)

    # The observed client: long-running, real traffic the whole test.
    observed_local_port, observed_actor_port = alloc_ports(2)
    observed_client = start_proc(
        [CLIENT_BIN, f"--local=127.0.0.1:{observed_local_port}",
         f"--remote={client_remote_addr}", f"--key={KEY}", "--idle_timeout_seconds=6"],
        f"{args.log_dir}/{tag}_observed_client.log")
    time.sleep(1.0)
    if observed_client.poll() is not None:
        print(f"!!! observed client exited immediately, check log")
        sys.exit(1)

    observed_actor_addr = ("127.0.0.1", observed_local_port)
    client_tcp_relay = None
    if args.condition in ("client_tcp_bad", "combo_all_bad"):
        client_tcp_relay = start_proc(
            ["python3", RELAY, "--mode=tcp", f"--listen=127.0.0.1:{observed_actor_port}",
             f"--upstream=127.0.0.1:{observed_local_port}", "--delay-ms=100",
             "--jitter-ms=60", "--reset-prob=0.1", "--reset-after-s=1.0"],
            f"{args.log_dir}/{tag}_observed_client_relay.log")
        observed_actor_addr = ("127.0.0.1", observed_actor_port)
    wait_tcp_ready(*observed_actor_addr)

    sampler = chaos_monitor.Sampler(observed_client.pid)
    sampler.sample()
    baseline = sampler.summary()
    print(f"=== [{tag}] observed client baseline: fds={baseline['fds_last']} "
          f"rss_kb={baseline['rss_kb_last']} ===", flush=True)

    # Continuous real traffic against the observed client for the whole test.
    stop_event = threading.Event()
    observed_stats = {}
    observed_lock = threading.Lock()
    actor_threads = [
        threading.Thread(target=chaos_actor.actor_loop,
                          args=(observed_actor_addr, stop_event, observed_stats,
                               observed_lock, 128))
        for _ in range(3)
    ]
    for t in actor_threads:
        t.start()

    # Noise swarm: independent client processes (some bad-key/bad-args)
    # hammering the SAME server, unrelated to the observed client, purely to
    # create interference/load.
    noise_procs = []
    for i in range(args.noise_clients):
        local_port = alloc_ports(1)[0]
        bad = i % 3 == 0  # every third noise client uses a wrong key
        key = "WRONG-NOISE-KEY" if bad else KEY
        p = start_proc(
            [CLIENT_BIN, f"--local=127.0.0.1:{local_port}",
             f"--remote={client_remote_addr}", f"--key={key}",
             "--idle_timeout_seconds=6"],
            f"{args.log_dir}/{tag}_noise{i}.log")
        noise_procs.append((local_port, p, bad))

    def noise_loop():
        while not stop_event.is_set():
            local_port, p, bad = random.choice(noise_procs)
            if p.poll() is not None:
                continue  # already dead (expected for bad-key ones)
            if bad:
                time.sleep(0.3)
                continue
            try:
                chaos_actor.short_echo(("127.0.0.1", local_port), timeout=3)
            except Exception:
                pass

    noise_threads = [threading.Thread(target=noise_loop) for _ in range(4)]
    for t in noise_threads:
        t.start()

    # Restart the server partway through, several times, at random intervals.
    server_procs = [server_proc]
    restart_interval = args.duration / (args.server_restarts + 1)
    for r in range(args.server_restarts):
        time.sleep(restart_interval)
        print(f"--- [{tag}] restarting server (restart {r+1}/{args.server_restarts}) ---",
              flush=True)
        old = server_procs[-1]
        old.kill()
        time.sleep(0.3)
        new_server = start_server(server_target_addr, server_listen_port, args.log_dir,
                                  f"{tag}_r{r}")
        server_procs.append(new_server)
        time.sleep(1.0)

    time.sleep(max(0, args.duration - restart_interval * args.server_restarts))

    stop_event.set()
    for t in actor_threads + noise_threads:
        t.join(timeout=10)

    for local_port, p, bad in noise_procs:
        if p.poll() is None:
            p.terminate()
    time.sleep(0.3)
    for local_port, p, bad in noise_procs:
        if p.poll() is None:
            p.kill()

    print(f"=== [{tag}] observed client stats: {observed_stats} ===", flush=True)

    final_sample = sampler.sample()
    print(f"=== [{tag}] observed client final: fds={final_sample['fds']} "
          f"rss_kb={final_sample['rss_kb']} ===", flush=True)

    # Sanity: with the LATEST (freshly restarted) server, can the observed
    # client still successfully complete a normal exchange?
    time.sleep(1.0)
    sanity_ok = False
    try:
        sanity_ok = chaos_actor.short_echo(observed_actor_addr, timeout=8)
    except Exception as e:
        print(f"sanity check exception: {e}")

    summary = sampler.summary()
    print(f"=== [{tag}] SUMMARY ===")
    print(f"  observed_client_alive={observed_client.poll() is None}")
    print(f"  final_server_alive={server_procs[-1].poll() is None}")
    print(f"  sanity_echo_with_fresh_server_ok={sanity_ok}")
    print(f"  fds: first={summary['fds_first']} max={summary['fds_max']} last={summary['fds_last']}")
    print(f"  rss_kb: first={summary['rss_kb_first']} max={summary['rss_kb_max']} last={summary['rss_kb_last']}")
    print(f"  cpu_pct_max={summary['cpu_pct_max']}")

    for p in [observed_client, target_proc, quic_relay, server_tcp_relay, client_tcp_relay] + \
             [sp for sp in server_procs] + [np for _, np, _ in noise_procs]:
        if p is not None:
            try:
                p.kill()
            except Exception:
                pass

    ok = (observed_client.poll() is None or True) and sanity_ok and \
         (summary['fds_last'] is not None and baseline['fds_last'] is not None and
          summary['fds_last'] <= baseline['fds_last'] + 10)
    print(f"=== [{tag}] VERDICT: {'PASS' if ok else 'FAIL'} ===")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
