#!/usr/bin/env python3
"""Stress the multi-instance SO_REUSEPORT + shared (--key-derived) session-
ticket path -- the one combination no other test in this suite exercises,
since every other test runs a single server instance.

quictun_server always binds --listen with SO_REUSEPORT (quictun_server_driver.cc),
so several instances share one port and the kernel spreads connections across
them by 4-tuple; the ticket key is derived from --key (quictun_certificate.cc)
so a 0-RTT ticket one instance issued still resumes on another. This does NOT
try to prove 0-RTT is accepted (reuseport_verify.py does that, deterministically) --
it asks the cruder but important question: does the combination stay UP under
churn, or does it crash / corrupt / leak / wedge?

Two instances on one port, a client on --udp_socket=4 --zero_rtt=true. It
fires bursts of concurrent short echoes (each a fresh TCP -> a stream on one
of the pooled connections, which land across both instances), lets connections
idle out between rounds so later ones resume via 0-RTT, and mid-run kills one
instance and restarts it -- reshuffling the reuseport group, the nastiest
case for it. Hard assertions: both processes survive, no echo comes back
CORRUPTED (wrong bytes, i.e. tunnels crossed), no fd/RSS leak, and a settled
batch after the churn all succeeds (it recovered). The count of connections
the client logged 0-RTT accepted on is reported for information.
"""
import argparse
import os
import re
import socket
import subprocess
import sys
import threading
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import chaos_monitor

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
SERVER_BIN = f"{REPO}/bazel-bin/quiche/quictun_server"
CLIENT_BIN = f"{REPO}/bazel-bin/quiche/quictun_client"
TARGET = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chaos_target.py")

KEY = "reuseport-key"
TARGET_PORT = 26830
LISTEN_PORT = 26831
LOCAL_PORT = 26832
IDLE_TIMEOUT = 6


def start_proc(cmd, log_path, env=None):
    f = open(log_path, "w")
    return subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, env=env)


def wait_tcp_ready(host, port, timeout=6):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection((host, port), timeout=0.3).close()
            return True
        except Exception:
            time.sleep(0.1)
    return False


def start_server(log_dir, tag):
    return start_proc(
        [SERVER_BIN, f"--listen=127.0.0.1:{LISTEN_PORT}",
         f"--target=127.0.0.1:{TARGET_PORT}", f"--key={KEY}",
         f"--idle_timeout_seconds={IDLE_TIMEOUT}", "--stderrthreshold=0"],
        f"{log_dir}/{tag}.log")


# Per-call random payload + strict equality: a "corrupt" result (full-length
# response that differs) is the signature of two concurrent tunnels' data
# being crossed -- a hard failure -- as opposed to a plain "fail" (short or no
# response), which under connection churn is tolerable and self-heals.
def short_echo(port, results, idx):
    payload = uuid.uuid4().bytes + os.urandom(48)
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        s.settimeout(3)
        s.sendall(payload)
        got = b""
        while len(got) < len(payload):
            chunk = s.recv(4096)
            if not chunk:
                break
            got += chunk
        s.close()
        if got == payload:
            results[idx] = "ok"
        elif len(got) >= len(payload):
            results[idx] = "corrupt"
        else:
            results[idx] = "fail"
    except Exception:
        results[idx] = "fail"


def burst(port, n):
    results = [None] * n
    threads = [threading.Thread(target=short_echo, args=(port, results, i))
               for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=6)
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--instances", type=int, default=2)
    ap.add_argument("--rounds", type=int, default=6)
    ap.add_argument("--burst", type=int, default=20)
    ap.add_argument("--log-dir", default="/tmp/quictun_reuseport_logs")
    args = ap.parse_args()
    os.makedirs(args.log_dir, exist_ok=True)

    target = start_proc(["python3", TARGET, str(TARGET_PORT)],
                        f"{args.log_dir}/target.log")
    time.sleep(0.5)

    servers = []
    for i in range(args.instances):
        servers.append(start_server(args.log_dir, f"server{i}"))
        time.sleep(0.6)
    # Every instance past the first only stays up because SO_REUSEPORT let it
    # bind the shared port -- without it, it would have EADDRINUSE'd and exited.
    bound = sum(1 for p in servers if p.poll() is None)
    print(f"=== instances bound on one port: {bound}/{args.instances} ===",
          flush=True)
    if bound < args.instances:
        print("!!! not all instances bound -- SO_REUSEPORT not in effect")
        for p in servers + [target]:
            p.kill()
        print("=== VERDICT: FAIL ===")
        sys.exit(1)

    client = start_proc(
        [CLIENT_BIN, f"--local=127.0.0.1:{LOCAL_PORT}",
         f"--remote=127.0.0.1:{LISTEN_PORT}", f"--key={KEY}", "--zero_rtt=true",
         f"--idle_timeout_seconds={IDLE_TIMEOUT}", "--udp_socket=4",
         "--conn_per_udp=1", "--stderrthreshold=0"],
        f"{args.log_dir}/client.log")
    time.sleep(1.0)
    if client.poll() is not None:
        print("!!! client exited immediately")
        for p in servers + [target]:
            p.kill()
        print("=== VERDICT: FAIL ===")
        sys.exit(1)
    wait_tcp_ready("127.0.0.1", LOCAL_PORT)

    sampler = chaos_monitor.Sampler(client.pid)
    sampler.sample()
    base = sampler.summary()
    print(f"=== baseline: fds={base['fds_last']} rss_kb={base['rss_kb_last']} ===",
          flush=True)

    totals = {"ok": 0, "fail": 0, "corrupt": 0}
    killed_round = args.rounds // 2
    for r in range(args.rounds):
        # Mid-run, reshuffle the reuseport group: kill one instance and bring
        # it back. Existing connections on the others may rehash and rebuild;
        # nothing should crash, and traffic should resume.
        if r == killed_round and args.instances >= 2:
            print(f"=== round {r+1}: killing+restarting instance 0 ===",
                  flush=True)
            servers[0].kill()
            servers[0].wait()
            time.sleep(0.5)
            servers[0] = start_server(args.log_dir, "server0_restart")
            time.sleep(0.8)

        res = burst(LOCAL_PORT, args.burst)
        for v in res:
            totals[v if v in totals else "fail"] += 1
        alive = [i for i, p in enumerate(servers) if p.poll() is None]
        cli_alive = client.poll() is None
        print(f"=== round {r+1}/{args.rounds}: ok={res.count('ok')} "
              f"fail={res.count('fail')} corrupt={res.count('corrupt')} "
              f"servers_alive={alive} client_alive={cli_alive} ===", flush=True)
        if not cli_alive or len(alive) < args.instances:
            print("!!! a process died during churn")
            break
        # Let connections idle out so the next round resumes via 0-RTT.
        time.sleep(IDLE_TIMEOUT + 1)

    # Recovery: after the churn, a settled batch must fully succeed.
    time.sleep(1.0)
    settle = burst(LOCAL_PORT, args.burst)
    recovered = settle.count("ok")
    print(f"=== settled batch after churn: ok={recovered}/{args.burst} "
          f"fail={settle.count('fail')} corrupt={settle.count('corrupt')} ===",
          flush=True)

    client_alive = client.poll() is None
    servers_alive = sum(1 for p in servers if p.poll() is None)

    # fd/RSS leak check, past one idle timeout so connections in their grace
    # window aren't miscounted -- same as the other pool tests.
    fds_ok = rss_ok = True
    if client_alive:
        time.sleep(IDLE_TIMEOUT + 2)
        sampler.sample()
        fin = sampler.summary()
        fds_ok = (fin['fds_last'] is not None and
                  fin['fds_last'] <= base['fds_last'] + 10)
        rss_ok = (fin['rss_kb_last'] is not None and
                  fin['rss_kb_last'] <= base['rss_kb_last'] + 100000)
        print(f"=== final: fds={fin['fds_last']} rss_kb={fin['rss_kb_last']} ===",
              flush=True)

    # Informational only: how often 0-RTT was actually accepted. Timing/hash
    # dependent, so not an assertion -- reuseport_verify.py is the real proof.
    try:
        clog = open(f"{args.log_dir}/client.log").read()
        early_true = len(re.findall(r"EarlyDataAccepted=true", clog))
        early_false = len(re.findall(r"EarlyDataAccepted=false", clog))
    except OSError:
        early_true = early_false = -1

    for p in servers + [client, target]:
        try:
            p.kill()
        except Exception:
            pass

    print("=== SUMMARY ===")
    print(f"  totals ok={totals['ok']} fail={totals['fail']} "
          f"corrupt={totals['corrupt']}")
    print(f"  recovered_after_churn={recovered}/{args.burst}")
    print(f"  client_alive={client_alive} servers_alive={servers_alive}/{args.instances}")
    print(f"  fds_ok={fds_ok} rss_ok={rss_ok}")
    print(f"  [info] 0-RTT accepted on {early_true} conns, "
          f"not-accepted on {early_false}")

    ok = (client_alive and servers_alive == args.instances and
          totals["corrupt"] == 0 and recovered == args.burst and
          fds_ok and rss_ok)
    print(f"=== VERDICT: {'PASS' if ok else 'FAIL'} ===")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
