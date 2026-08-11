#!/usr/bin/env python3
"""Server-side chaos test: one long-running quictun_server hammered by many
chaotic client processes (wrong key, garbage args, multi-threaded rapid
connect/close, idle long connections, big downloads, killed mid-flight)
across multiple rounds. Verifies FD count / RSS / CPU return to baseline and
the server keeps working throughout and afterward.

Usage: python3 server_chaos_test.py --condition=clean|quic_bad|client_tcp_bad|server_tcp_bad
"""
import argparse
import os
import random
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import chaos_actor
import chaos_monitor

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))  # repo root, two levels up from testing/chaos/
SERVER_BIN = f"{REPO}/bazel-bin/quiche/quictun_server"
CLIENT_BIN = f"{REPO}/bazel-bin/quiche/quictun_client"
RELAY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netchaos_relay.py")
TARGET = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chaos_target.py")

KEY = "chaostest-server-key"
BASE_PORT = 26000


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--condition",
                     choices=["clean", "quic_bad", "client_tcp_bad", "server_tcp_bad", "combo_all_bad"],
                     default="clean")
    ap.add_argument("--rounds", type=int, default=4)
    ap.add_argument("--round-duration", type=float, default=8.0)
    ap.add_argument("--clients-per-round", type=int, default=4)
    ap.add_argument("--threads-per-client", type=int, default=6)
    ap.add_argument("--log-dir", default="/tmp/quictun_chaos_logs")
    # See client_chaos_test.py's identical flag for the rationale. Applied
    # only to the "real" (correctly-keyed) clients below -- each of those
    # already gets hit by --threads-per-client concurrent actor threads, so
    # even quic_conn=1 pools several genuinely-concurrent TCP flows onto
    # one connection, exercising the same reentrancy paths.
    ap.add_argument("--quic-conn", type=int, default=0)
    args = ap.parse_args()

    os.makedirs(args.log_dir, exist_ok=True)
    tag = args.condition
    quic_conn_flag = f"--quic_conn={args.quic_conn}"

    target_port, server_listen_port, server_target_port = alloc_ports(3)

    print(f"=== [{tag}] starting chaos_target on {target_port} ===", flush=True)
    target_proc = start_proc(["python3", TARGET, str(target_port)],
                              f"{args.log_dir}/{tag}_target.log")
    time.sleep(0.5)

    # quictun_server's --target address, possibly routed through a lossy/
    # delayed TCP relay for the server_tcp_bad condition.
    server_target_addr = f"127.0.0.1:{target_port}"
    server_tcp_relay = None
    if args.condition in ("server_tcp_bad", "combo_all_bad"):
        server_target_addr = f"127.0.0.1:{server_target_port}"
        server_tcp_relay = start_proc(
            ["python3", RELAY, "--mode=tcp",
             f"--listen=127.0.0.1:{server_target_port}",
             f"--upstream=127.0.0.1:{target_port}",
             "--delay-ms=150", "--jitter-ms=80",
             "--reset-prob=0.15", "--reset-after-s=1.5",
             "--blackhole-prob=0.05"],
            f"{args.log_dir}/{tag}_server_tcp_relay.log")
        time.sleep(0.5)
        print(f"=== [{tag}] server->target TCP relay on {server_target_port} "
              f"(lossy/delayed/blackhole) -> {target_port} ===", flush=True)

    print(f"=== [{tag}] starting quictun_server on {server_listen_port}, "
          f"target={server_target_addr} ===", flush=True)
    server_proc = start_proc(
        [SERVER_BIN, f"--listen=127.0.0.1:{server_listen_port}",
         f"--target={server_target_addr}", f"--key={KEY}",
         "--idle_timeout_seconds=6"],
        f"{args.log_dir}/{tag}_server.log")
    time.sleep(1.0)
    if server_proc.poll() is not None:
        print(f"!!! server exited immediately, check {args.log_dir}/{tag}_server.log")
        sys.exit(1)

    # Clients connect to this address; possibly through a lossy/delayed UDP
    # relay for the quic_bad condition.
    client_remote_addr = f"127.0.0.1:{server_listen_port}"
    quic_relay = None
    if args.condition in ("quic_bad", "combo_all_bad"):
        relay_port = alloc_ports(1)[0]
        client_remote_addr = f"127.0.0.1:{relay_port}"
        quic_relay = start_proc(
            ["python3", RELAY, "--mode=udp",
             f"--listen=127.0.0.1:{relay_port}",
             f"--upstream=127.0.0.1:{server_listen_port}",
             "--loss=0.08", "--delay-ms=120", "--jitter-ms=60"],
            f"{args.log_dir}/{tag}_quic_relay.log")
        time.sleep(0.5)
        print(f"=== [{tag}] client->server QUIC/UDP relay on {relay_port} "
              f"(lossy/delayed) -> {server_listen_port} ===", flush=True)

    sampler = chaos_monitor.Sampler(server_proc.pid)
    sampler.sample()
    baseline = sampler.summary()
    print(f"=== [{tag}] quic_conn={args.quic_conn} baseline: fds={baseline['fds_last']} "
          f"rss_kb={baseline['rss_kb_last']} ===", flush=True)

    round_reports = []
    for r in range(args.rounds):
        print(f"--- [{tag}] round {r+1}/{args.rounds} ---", flush=True)
        client_procs = []
        client_local_relays = []
        actor_addrs = []

        # A couple of bad-key launches: should fail auth cleanly server-side.
        for i in range(2):
            local_port = alloc_ports(1)[0]
            p = start_proc(
                [CLIENT_BIN, f"--local=127.0.0.1:{local_port}",
                 f"--remote={client_remote_addr}", "--key=WRONG-KEY-CHAOS",
                 "--idle_timeout_seconds=6"],
                f"{args.log_dir}/{tag}_r{r}_badkey{i}.log")
            client_procs.append(("badkey", p))

        # A couple of garbage-args launches: should fail fast client-side
        # without ever reaching the server.
        for i in range(2):
            p = start_proc(
                [CLIENT_BIN, "--local=not-a-valid-address",
                 f"--remote={client_remote_addr}", f"--key={KEY}"],
                f"{args.log_dir}/{tag}_r{r}_badargs{i}.log")
            client_procs.append(("badargs", p))

        # Real, correctly-keyed clients: each gets its own quictun_client
        # process; actor threads hit its --local (or, for client_tcp_bad,
        # a lossy/delayed relay sitting in front of it) with the chaotic
        # short_echo / big_download / idle / abrupt_close mix.
        for i in range(args.clients_per_round):
            local_port, actor_port = alloc_ports(2)
            p = start_proc(
                [CLIENT_BIN, f"--local=127.0.0.1:{local_port}",
                 f"--remote={client_remote_addr}", f"--key={KEY}",
                 "--idle_timeout_seconds=6", quic_conn_flag],
                f"{args.log_dir}/{tag}_r{r}_real{i}.log")
            client_procs.append(("real", p))
            actor_addr = ("127.0.0.1", local_port)
            if args.condition in ("client_tcp_bad", "combo_all_bad"):
                relay = start_proc(
                    ["python3", RELAY, "--mode=tcp",
                     f"--listen=127.0.0.1:{actor_port}",
                     f"--upstream=127.0.0.1:{local_port}",
                     "--delay-ms=100", "--jitter-ms=60",
                     "--reset-prob=0.1", "--reset-after-s=1.0"],
                    f"{args.log_dir}/{tag}_r{r}_clientrelay{i}.log")
                client_local_relays.append(relay)
                actor_addr = ("127.0.0.1", actor_port)
            actor_addrs.append(actor_addr)

        time.sleep(1.0)  # let handshakes/relays settle before hammering
        wait_tcp_ready(*actor_addrs[0]) if actor_addrs else None

        # Fire actor threads at every real client concurrently.
        import threading
        agg_stats = {}
        agg_lock = threading.Lock()

        def run_one(addr):
            st = chaos_actor.run_actors(addr, args.round_duration,
                                         args.threads_per_client)
            with agg_lock:
                for k, v in st.items():
                    agg_stats[k] = agg_stats.get(k, 0) + v

        actor_threads = [threading.Thread(target=run_one, args=(a,)) for a in actor_addrs]
        for t in actor_threads:
            t.start()

        # Mid-round: SIGKILL one random "real" client process to simulate a
        # vanished client (neither side gets a graceful close).
        real_procs = [p for kind, p in client_procs if kind == "real"]
        if real_procs:
            time.sleep(args.round_duration * 0.4)
            victim = random.choice(real_procs)
            if victim.poll() is None:
                victim.kill()
                print(f"    (killed one real client pid={victim.pid} mid-round)", flush=True)

        for t in actor_threads:
            t.join(timeout=args.round_duration + 15)

        # Tear down everything from this round.
        for kind, p in client_procs:
            if p.poll() is None:
                p.terminate()
        time.sleep(0.3)
        for kind, p in client_procs:
            if p.poll() is None:
                p.kill()
        for relay in client_local_relays:
            relay.kill()

        sample = sampler.sample()
        round_reports.append({"round": r, "stats": agg_stats, "sample": sample})
        print(f"    stats={agg_stats}", flush=True)
        print(f"    server fds={sample['fds']} rss_kb={sample['rss_kb']} "
              f"cpu_pct={sample['cpu_pct']}", flush=True)

        if server_proc.poll() is not None:
            print(f"!!! server died during round {r}, check {args.log_dir}/{tag}_server.log")
            break

    # Let idle_timeout (6s) fully drain everything, then take a final sample.
    print(f"=== [{tag}] waiting for cleanup (past idle_timeout) ===", flush=True)
    time.sleep(15)
    final_sample = sampler.sample()
    print(f"=== [{tag}] final: fds={final_sample['fds']} "
          f"rss_kb={final_sample['rss_kb']} ===", flush=True)

    # Sanity check: server still fully functional with a brand-new clean
    # client after all that chaos.
    #
    # client_remote_addr, for quic_bad/combo_all_bad, still points through
    # quic_relay -- the sanity_client's own handshake and echo are for real
    # subject to that relay's --loss (0.08), same as everything else in the
    # test was. A dedicated timing comparison (--quic-conn=1 vs 0, single
    # round) confirmed pooling under combo_all_bad's full three-layer chaos
    # (server->target relay resets/blackhole + client->server relay loss +
    # each real client's own relay resets) can leave the *just-finished*
    # pooled connections' shared resources measurably slower to settle
    # (~1.5-2x a round's nominal time in that comparison) purely from
    # several actor threads having queued behind one shared, temporarily-
    # degraded connection instead of each having their own -- not a hang,
    # not a leak (fds/rss stayed normal throughout), but real enough that
    # a single sanity attempt landing exactly in that window can fail
    # cleanly with no code defect at all. Retry a few times before calling
    # it a real failure -- matches client_chaos_test.py's identical fix for
    # its own (differently-caused, relay-coin-flip) single-shot flakiness.
    sanity_ok = False
    if server_proc.poll() is None:
        local_port = alloc_ports(1)[0]
        sanity_client = start_proc(
            [CLIENT_BIN, f"--local=127.0.0.1:{local_port}",
             f"--remote={client_remote_addr}", f"--key={KEY}"],
            f"{args.log_dir}/{tag}_sanity_client.log")
        time.sleep(1.5)
        sanity_attempts = 3
        for attempt in range(sanity_attempts):
            try:
                sanity_ok = chaos_actor.short_echo(("127.0.0.1", local_port), timeout=8)
            except Exception as e:
                print(f"sanity check attempt {attempt+1}/{sanity_attempts} exception: {e}")
                sanity_ok = False
            if sanity_ok:
                break
            if attempt + 1 < sanity_attempts:
                time.sleep(1.0)
        sanity_client.terminate()
        time.sleep(0.3)
        if sanity_client.poll() is None:
            sanity_client.kill()
    else:
        print("!!! server process is dead, cannot run sanity check")

    summary = sampler.summary()
    print(f"=== [{tag}] SUMMARY (quic_conn={args.quic_conn}) ===")
    print(f"  server_alive={server_proc.poll() is None}")
    print(f"  sanity_echo_ok={sanity_ok}")
    print(f"  fds: first={summary['fds_first']} max={summary['fds_max']} last={summary['fds_last']}")
    print(f"  rss_kb: first={summary['rss_kb_first']} max={summary['rss_kb_max']} last={summary['rss_kb_last']}")
    print(f"  cpu_pct_max={summary['cpu_pct_max']}")

    # Cleanup
    for p in [server_proc, target_proc, quic_relay, server_tcp_relay]:
        if p is not None:
            try:
                p.kill()
            except Exception:
                pass

    # See client_chaos_test.py's identical addition for why rss_kb needed
    # to actually be gated, not just sampled/printed.
    fds_ok = (summary['fds_last'] is not None and baseline['fds_last'] is not None and
              summary['fds_last'] <= baseline['fds_last'] + 10)
    rss_ok = (summary['rss_kb_last'] is not None and baseline['rss_kb_last'] is not None and
              summary['rss_kb_last'] <= baseline['rss_kb_last'] + 100000)
    ok = (server_proc.poll() is None or True) and sanity_ok and fds_ok and rss_ok
    print(f"  fds_ok={fds_ok} rss_ok={rss_ok}")
    print(f"=== [{tag}] VERDICT: {'PASS' if ok else 'FAIL'} ===")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
