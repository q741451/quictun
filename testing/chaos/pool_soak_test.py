#!/usr/bin/env python3
"""Coverage-gap test: a slow, sustained leak in the --quic_conn pooling
machinery (a StreamTcp/StreamTarget entry, a stream_delegates_ entry, an
alarm never cancelled -- anything that leaks a small, fixed amount per
stream open/close cycle rather than per test run) wouldn't show up in any
other test in this suite: everything else compares one "before" snapshot
against one "after" snapshot from a run lasting well under a minute, which
is long enough to catch a leak that's large per-cycle but not one that's
merely *nonzero* per-cycle -- exactly the harder, more realistic case for
a connection-pooling feature specifically designed to keep connections
open and reused for a long time.

Runs several worker threads continuously opening/closing short TCP flows
through a --quic_conn-pooled client for a sustained duration, sampling
both processes' fd count and RSS at regular intervals throughout (not
just first/last), then compares the average of the second half of samples
against the first half: a real leak trends upward across the whole run;
one-time startup growth (allocator warm-up, initial buffers) shows up
early and then plateaus, which this specifically tolerates by looking at
the trend rather than the absolute final value.

Usage: python3 pool_soak_test.py [--duration=180] [--quic-conn=2]
"""
import argparse
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

KEY = "pool-soak-key"


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


def worker_loop(port, stop_event, counters, lock):
    payload = os.urandom(48)
    while not stop_event.is_set():
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=2)
            s.sendall(payload)
            got = b""
            while len(got) < len(payload):
                chunk = s.recv(4096)
                if not chunk:
                    break
                got += chunk
            s.close()
            with lock:
                counters["ok" if got == payload else "fail"] = \
                    counters.get("ok" if got == payload else "fail", 0) + 1
        except Exception:
            with lock:
                counters["exc"] = counters.get("exc", 0) + 1
        time.sleep(0.05)


def analyze_trend(samples, key, label, threshold):
    """samples: list of dicts with 't' and `key`. Compares the average of
    the second half against the first half (dropping the very first
    sample -- startup transient). Returns (ok, detail_str)."""
    vals = [s[key] for s in samples if s.get(key) is not None]
    if len(vals) < 6:
        return True, f"{label}: only {len(vals)} samples, skipping trend check"
    vals = vals[1:]  # drop the immediate-post-startup sample
    n = len(vals)
    early = vals[: n // 2]
    late = vals[n // 2:]
    early_avg = sum(early) / len(early)
    late_avg = sum(late) / len(late)
    delta = late_avg - early_avg
    ok = delta <= threshold
    verdict = "OK" if ok else "TRENDING UP"
    return ok, (f"{label}: early_avg={early_avg:.1f} late_avg={late_avg:.1f} "
                f"delta={delta:+.1f} threshold={threshold} -> {verdict}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=float, default=180.0)
    ap.add_argument("--sample-interval", type=float, default=10.0)
    ap.add_argument("--quic-conn", type=int, default=2)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--log-dir", default="/tmp/quictun_pool_soak_logs")
    args = ap.parse_args()

    os.makedirs(args.log_dir, exist_ok=True)
    tag = f"soak_qc{args.quic_conn}"

    target_port, server_port, client_port = 29700, 29701, 29702

    target_proc = start_proc(["python3", TARGET, str(target_port)],
                              f"{args.log_dir}/{tag}_target.log")
    time.sleep(0.5)
    server_proc = start_proc(
        [SERVER_BIN, f"--listen=127.0.0.1:{server_port}",
         f"--target=127.0.0.1:{target_port}", f"--key={KEY}"],
        f"{args.log_dir}/{tag}_server.log")
    time.sleep(1.0)
    client_proc = start_proc(
        [CLIENT_BIN, f"--local=127.0.0.1:{client_port}",
         f"--remote=127.0.0.1:{server_port}", f"--key={KEY}",
         f"--quic_conn={args.quic_conn}"],
        f"{args.log_dir}/{tag}_client.log")
    time.sleep(1.0)
    if client_proc.poll() is not None:
        print(f"!!! [{tag}] client exited immediately")
        sys.exit(1)

    wait_tcp_ready("127.0.0.1", client_port)

    print(f"=== [{tag}] running {args.workers} workers continuously opening/"
          f"closing tunnels through --quic_conn={args.quic_conn} for "
          f"{args.duration:.0f}s, sampling every {args.sample_interval:.0f}s ===",
          flush=True)

    stop_event = threading.Event()
    counters = {}
    lock = threading.Lock()
    threads = [threading.Thread(target=worker_loop,
                                 args=(client_port, stop_event, counters, lock))
               for _ in range(args.workers)]
    for t in threads:
        t.start()

    client_sampler = chaos_monitor.Sampler(client_proc.pid)
    server_sampler = chaos_monitor.Sampler(server_proc.pid)
    samples = []
    t0 = time.time()
    next_sample = t0
    while time.time() - t0 < args.duration:
        now = time.time()
        if now >= next_sample:
            cs = client_sampler.sample()
            ss = server_sampler.sample()
            with lock:
                snap_counters = dict(counters)
            samples.append({
                "t": now - t0,
                "client_fds": cs["fds"], "client_rss_kb": cs["rss_kb"],
                "server_fds": ss["fds"], "server_rss_kb": ss["rss_kb"],
            })
            print(f"  t={now - t0:6.1f}s client_fds={cs['fds']} "
                  f"client_rss_kb={cs['rss_kb']} server_fds={ss['fds']} "
                  f"server_rss_kb={ss['rss_kb']} counters={snap_counters}",
                  flush=True)
            next_sample += args.sample_interval
        time.sleep(min(0.5, max(0.05, next_sample - time.time())))

    stop_event.set()
    for t in threads:
        t.join(timeout=5)

    client_alive = client_proc.poll() is None
    server_alive = server_proc.poll() is None
    print(f"=== [{tag}] client_alive={client_alive} server_alive={server_alive} "
          f"final_counters={counters} ===", flush=True)

    for p in (client_proc, server_proc, target_proc):
        try:
            p.kill()
        except Exception:
            pass

    fail_rate_ok = True
    total = sum(counters.get(k, 0) for k in ("ok", "fail", "exc"))
    if total > 0:
        fail_rate = 1 - (counters.get("ok", 0) / total)
        fail_rate_ok = fail_rate < 0.05
        print(f"=== [{tag}] fail_rate={fail_rate:.3f} (threshold 0.05) "
              f"fail_rate_ok={fail_rate_ok} ===", flush=True)

    checks = [
        analyze_trend(samples, "client_fds", "client fds", threshold=5),
        analyze_trend(samples, "client_rss_kb", "client rss_kb", threshold=8000),
        analyze_trend(samples, "server_fds", "server fds", threshold=5),
        analyze_trend(samples, "server_rss_kb", "server rss_kb", threshold=8000),
    ]
    print("=== SUMMARY ===")
    trend_ok = True
    for ok, detail in checks:
        print(f"  {detail}")
        trend_ok = trend_ok and ok

    verdict_ok = client_alive and server_alive and fail_rate_ok and trend_ok
    print(f"=== [{tag}] VERDICT: {'PASS' if verdict_ok else 'FAIL'} ===", flush=True)
    sys.exit(0 if verdict_ok else 1)


if __name__ == "__main__":
    main()
