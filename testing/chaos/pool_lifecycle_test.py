#!/usr/bin/env python3
"""Coverage-gap test: --quic_conn pool slot lifecycle -- removal
(auto-rebuild after a pooled connection's path silently dies),
allocation (round-robin is genuinely deterministic-fair across slots),
and the "dry queue" consequence of that same determinism (a new TCP can
land on a slot whose streams are already full while a *different* slot
currently has room, and just queues there instead of getting redirected
-- see AcceptLoop()'s own comment in quictun_client_driver.cc for why:
round-robin picks blind to current occupancy, only checking nullptr/
closed()).

None of this needs any internal logging to verify: pool assignment
order is fully deterministic from request order alone (round_robin_next_
increments unconditionally on every accepted TCP -- see
quictun_client_driver.cc), so slot behaviour is observable purely from
which requests succeed. Connection counting via each process's own UDP
sockets is gone: the client multiplexes every QUIC connection onto one
shared socket, so /proc says nothing about how many exist (pool_cap_test.py
now uses the server's admission control for that instead). Likewise the
relay can no longer blackhole one slot's path while sparing a sibling --
there is only one path -- so "removal" now kills the shared path for all
of them and checks the rebuild. fd/RSS sampled throughout every scenario
(chaos_monitor.Sampler) rather than just checked once at the end.

Usage: python3 pool_lifecycle_test.py
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
RELAY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netchaos_relay.py")
TARGET = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chaos_target.py")

KEY = "pool-lifecycle-key"
BASE_PORT = 27100


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


def wait_for_client_log_ready(client_log, timeout=5):
    """Readiness check that does NOT touch the client's --local TCP port
    at all -- unlike wait_tcp_ready(), which connects-then-immediately-
    closes and is fine for scenarios indifferent to pool assignment, but
    is a genuine bug for anything (like scenario_removal()) that depends
    on an EXACT slot index: that connect+close is still a real accepted
    TCP as far as AcceptLoop()'s round robin is concerned (see
    quictun_client_driver.cc -- idx assignment happens unconditionally
    on every accept(), whether or not the peer ever sends a byte), so it
    silently consumes round-robin turn 0 and creates slot 0's real QUIC
    connection before the scenario's own first HeldConn ever connects --
    offsetting every later slot assignment by one. Confirmed via a real
    repro: this exact offset was why blackholing "slot 0" left the
    supposedly-untouched sibling dead and the supposedly-blackholed slot
    fine -- flow index 0 at the relay was this phantom probe connection
    (later reused by round-robin wraparound), not the scenario's own
    first request. Polling the client's own startup log for its
    "listening on" line instead means zero extra TCP activity touches
    the pool at all."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            content = open(client_log).read()
        except FileNotFoundError:
            content = ""
        if "listening on" in content:
            return True
        time.sleep(0.05)
    return False


class HeldConn:
    def __init__(self, idx, port):
        self.idx = idx
        self.port = port
        self.sock = None
        self.got_echo = False
        self.error = None
        self.release_event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

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

    def probe(self, timeout=3):
        """One-shot external liveness probe: send+recv on the SAME
        already-connected socket. True/False/raises like a normal
        socket op; doesn't touch got_echo/release_event."""
        self.sock.settimeout(timeout)
        self.sock.sendall(f"probe-{self.idx}\n".encode())
        data = self.sock.recv(64)
        return bool(data)


def scenario_removal(log_dir):
    """The pooled connections' shared path silently dies (relay blackhole
    -- see netchaos_relay.py's blackhole_flow()). Expected: the open TCPs
    fail, the client neither dies nor spins, and once the path is back and
    idle_timeout has marked the dead connections closed(), the next TCPs
    round-robin onto those same slot indices, get genuinely new underlying
    connections, and succeed normally."""
    tag = "removal"
    # Must outlast this scenario's own probe sequence -- see the earlier
    # repro where 4s let the connections idle out from the test's own
    # pacing rather than from the blackhole.
    idle_timeout_s = 15
    target_port, server_port, relay_port, client_port = alloc_ports(4)

    target_proc = start_proc(["python3", TARGET, str(target_port)],
                              f"{log_dir}/{tag}_target.log")
    time.sleep(0.5)
    server_proc = start_proc(
        [SERVER_BIN, f"--listen=127.0.0.1:{server_port}",
         f"--target=127.0.0.1:{target_port}", f"--key={KEY}",
         f"--idle_timeout_seconds={idle_timeout_s}"],
        f"{log_dir}/{tag}_server.log")
    time.sleep(1.0)

    trigger_file = f"{log_dir}/{tag}_blackhole_trigger"
    if os.path.exists(trigger_file):
        os.remove(trigger_file)
    relay_log = f"{log_dir}/{tag}_relay.log"
    relay_cmd = ["python3", RELAY, "--mode=udp", f"--listen=127.0.0.1:{relay_port}",
                 f"--upstream=127.0.0.1:{server_port}",
                 f"--blackhole-trigger-file={trigger_file}"]
    relay_proc = start_proc(relay_cmd, relay_log)
    time.sleep(0.5)

    client_proc = start_proc(
        [CLIENT_BIN, f"--local=127.0.0.1:{client_port}",
         f"--remote=127.0.0.1:{relay_port}", f"--key={KEY}",
         f"--idle_timeout_seconds={idle_timeout_s}", "--quic_conn=2"],
        f"{log_dir}/{tag}_client.log")
    time.sleep(1.0)
    wait_for_client_log_ready(f"{log_dir}/{tag}_client.log")

    client_sampler = chaos_monitor.Sampler(client_proc.pid)
    server_sampler = chaos_monitor.Sampler(server_proc.pid)

    def sample(label):
        cs = client_sampler.sample()
        ss = server_sampler.sample()
        print(f"    [{label}] client fds={cs['fds']} rss_kb={cs['rss_kb']} | "
              f"server fds={ss['fds']} rss_kb={ss['rss_kb']}", flush=True)

    sample("baseline")

    # 2 requests, held open -- deterministically slot 0 then slot 1 (see
    # AcceptLoop()'s round-robin, which increments unconditionally on every
    # accepted TCP). Serialized so each slot's handshake completes on its own.
    c0 = HeldConn(0, client_port)
    c0.start()
    t0 = time.time()
    while time.time() - t0 < 5.0 and not c0.got_echo:
        time.sleep(0.05)
    c1 = HeldConn(1, client_port)
    c1.start()
    t0 = time.time()
    while time.time() - t0 < 5.0 and not c1.got_echo:
        time.sleep(0.05)
    print(f"    initial: slot0_ok={c0.got_echo} slot1_ok={c1.got_echo}")
    sample("both slots up")
    if not (c0.got_echo and c1.got_echo):
        print(f"!!! [{tag}] setup failed, aborting")
        for p in (client_proc, relay_proc, server_proc, target_proc):
            p.kill()
        return False

    # Flow 0 is the client's one shared UDP socket, so this is every pooled
    # connection's path vanishing at once -- no FIN, no RST, nothing.
    print("    === blackholing the shared path ===", flush=True)
    with open(trigger_file, "w") as f:
        f.write("0")
    time.sleep(2.0)  # let the relay's poll loop pick it up

    # Both open connections must fail now. Retried: a lone success could be
    # data already in flight when the blackhole engaged.
    fail_count = 0
    for c in (c0, c1):
        for _ in range(3):
            try:
                if not c.probe(timeout=2):
                    fail_count += 1
            except Exception:
                fail_count += 1
            time.sleep(0.3)
    path_dead = fail_count >= 4
    print(f"    blackholed path: {fail_count}/6 probe attempts failed (expect >= 4)")
    sample("path blackholed")

    c0.release()
    c1.release()

    # Restore the path: the relay's blackhole list is permanent for its own
    # lifetime, so a fresh relay on the same port is how the path comes back.
    relay_proc.kill()
    time.sleep(0.3)
    relay_proc = start_proc(relay_cmd, relay_log + ".2")
    time.sleep(0.5)

    print(f"    waiting {idle_timeout_s + 2}s past idle_timeout for the dead "
          f"connections to self-detect ===", flush=True)
    time.sleep(idle_timeout_s + 2)
    sample("past idle_timeout")

    # Two MORE requests: round-robin continues (2 accepted so far), so
    # idx=2%2=0 then idx=3%2=1 -- both dead slots, both must be rebuilt.
    c2 = HeldConn(2, client_port)
    c3 = HeldConn(3, client_port)
    c2.start()
    time.sleep(0.1)
    c3.start()
    time.sleep(3.0)
    print(f"    rebuild: slot0_new_conn_ok={c2.got_echo} "
          f"slot1_new_conn_ok={c3.got_echo}")
    sample("after rebuild")

    c2.release()
    c3.release()

    final_alive = client_proc.poll() is None and server_proc.poll() is None
    # A dead path with nothing to read is exactly the shape that produced
    # the historical POLLERR/writable spins (6990cb05d, c15f3eb57), so the
    # samples taken across the blackhole window are gated, not just printed.
    cpu_max = client_sampler.summary()["cpu_pct_max"]
    cpu_ok = cpu_max is None or cpu_max < 50.0
    print(f"    final: client_alive={client_proc.poll() is None} "
          f"server_alive={server_proc.poll() is None} "
          f"client_cpu_pct_max={cpu_max} (expect < 50)")

    for p in (client_proc, relay_proc, server_proc, target_proc):
        try:
            p.kill()
        except Exception:
            pass

    ok = path_dead and c2.got_echo and c3.got_echo and final_alive and cpu_ok
    print(f"=== [{tag}] VERDICT: {'PASS' if ok else 'FAIL'} ===", flush=True)
    return ok


def scenario_allocation(log_dir):
    """Round-robin fairness, made externally observable: cap each
    connection at exactly 1 stream (--max_streams_per_connection=1), so
    "did request i land on a *different* slot than request i-1" is
    directly readable from "did it succeed immediately" (a repeat visit
    to an already-occupied slot would queue, not succeed) -- no internal
    logging needed. N requests through an N-slot pool should all
    succeed immediately, each on its own distinct slot."""
    tag = "allocation"
    n_slots = 4
    target_port, server_port, client_port = alloc_ports(3)

    target_proc = start_proc(["python3", TARGET, str(target_port)],
                              f"{log_dir}/{tag}_target.log")
    time.sleep(0.5)
    server_proc = start_proc(
        [SERVER_BIN, f"--listen=127.0.0.1:{server_port}",
         f"--target=127.0.0.1:{target_port}", f"--key={KEY}",
         "--idle_timeout_seconds=20", "--max_streams_per_connection=1"],
        f"{log_dir}/{tag}_server.log")
    time.sleep(1.0)
    client_proc = start_proc(
        [CLIENT_BIN, f"--local=127.0.0.1:{client_port}",
         f"--remote=127.0.0.1:{server_port}", f"--key={KEY}",
         "--idle_timeout_seconds=20", f"--quic_conn={n_slots}"],
        f"{log_dir}/{tag}_client.log")
    time.sleep(1.0)
    wait_for_client_log_ready(f"{log_dir}/{tag}_client.log")

    client_sampler = chaos_monitor.Sampler(client_proc.pid)
    server_sampler = chaos_monitor.Sampler(server_proc.pid)
    client_sampler.sample()
    server_sampler.sample()
    print(f"    baseline: client_fds={client_sampler.history[-1]['fds']}",
          flush=True)

    print(f"    === firing {n_slots} sequential held requests through a "
          f"{n_slots}-slot pool, each connection capped at 1 stream ===",
          flush=True)
    conns = [HeldConn(i, client_port) for i in range(n_slots)]
    for c in conns:
        c.start()
        time.sleep(0.15)  # sequential, not simultaneous -- makes the
                           # round-robin order unambiguous
    time.sleep(1.5)

    client_sampler.sample()
    server_sampler.sample()
    results = [c.got_echo for c in conns]
    print(f"    per-request success: {results} (expect all True -- each "
          f"landed on its own distinct, previously-idle slot)")
    print(f"    client fds={client_sampler.history[-1]['fds']} "
          f"rss_kb={client_sampler.history[-1]['rss_kb']} | "
          f"server fds={server_sampler.history[-1]['fds']} "
          f"rss_kb={server_sampler.history[-1]['rss_kb']}")

    for c in conns:
        c.release()
    time.sleep(0.5)
    final_alive = client_proc.poll() is None and server_proc.poll() is None

    for p in (client_proc, server_proc, target_proc):
        try:
            p.kill()
        except Exception:
            pass

    ok = all(results) and final_alive
    print(f"=== [{tag}] VERDICT: {'PASS' if ok else 'FAIL'} ===", flush=True)
    return ok


def scenario_dry_queue(log_dir):
    """The flip side of deterministic round-robin: a new TCP is assigned
    to whichever slot is "next" by request COUNT, not by which slot
    currently has spare stream capacity -- so it can land on an
    already-full slot and queue there even while a DIFFERENT slot has
    room right now. --quic_conn=2, --max_streams_per_connection=2:
    fills both slots (2 streams each), frees ONE stream on slot 1 only,
    then fires a new request -- round-robin's next turn is slot 0 (still
    full), so the new request should queue despite slot 1 having a free
    stream. Only releasing something on slot 0 itself -- not slot 1 --
    should free it."""
    tag = "dry_queue"
    target_port, server_port, client_port = alloc_ports(3)

    target_proc = start_proc(["python3", TARGET, str(target_port)],
                              f"{log_dir}/{tag}_target.log")
    time.sleep(0.5)
    server_proc = start_proc(
        [SERVER_BIN, f"--listen=127.0.0.1:{server_port}",
         f"--target=127.0.0.1:{target_port}", f"--key={KEY}",
         "--idle_timeout_seconds=20", "--max_streams_per_connection=2"],
        f"{log_dir}/{tag}_server.log")
    time.sleep(1.0)
    client_proc = start_proc(
        [CLIENT_BIN, f"--local=127.0.0.1:{client_port}",
         f"--remote=127.0.0.1:{server_port}", f"--key={KEY}",
         "--idle_timeout_seconds=20", "--quic_conn=2"],
        f"{log_dir}/{tag}_client.log")
    time.sleep(1.0)
    wait_for_client_log_ready(f"{log_dir}/{tag}_client.log")

    client_sampler = chaos_monitor.Sampler(client_proc.pid)
    server_sampler = chaos_monitor.Sampler(server_proc.pid)
    client_sampler.sample()
    server_sampler.sample()

    # Deterministic round-robin order (2 slots): req0->slot0, req1->slot1,
    # req2->slot0 (fills it, 2/2), req3->slot1 (fills it, 2/2).
    conns = [HeldConn(i, client_port) for i in range(4)]
    for c in conns:
        c.start()
        time.sleep(0.1)
    time.sleep(1.5)
    print(f"    fill: {[c.got_echo for c in conns]} (expect all True -- "
          f"slot0=[0,2] slot1=[1,3], both now full at 2/2)")
    client_sampler.sample()
    server_sampler.sample()

    # Free ONE stream on slot 1 only (release conn index 1).
    print(f"    === releasing conn 1 (slot 1) only -- slot 1 now has 1 "
          f"free stream, slot 0 stays full ===", flush=True)
    conns[1].release()
    time.sleep(0.5)

    # req4: round-robin's next turn is idx=4%2=0 -- slot 0, still full.
    # Expected: this queues, NOT redirected to slot 1's free stream.
    c4 = HeldConn(4, client_port)
    c4.start()
    time.sleep(1.5)
    print(f"    new request (round-robin turn = slot 0, which is still "
          f"full): got_echo={c4.got_echo} (expect False -- dry-queued on "
          f"slot 0 despite slot 1 having a free stream)")
    client_sampler.sample()
    server_sampler.sample()
    dry_queued = not c4.got_echo

    # Now free slot 0 (release conn index 0) -- THIS should let c4 through.
    print(f"    === releasing conn 0 (slot 0) -- should free the slot c4 "
          f"is actually queued on ===", flush=True)
    conns[0].release()
    t0 = time.time()
    while time.time() - t0 < 8.0 and not c4.got_echo:
        time.sleep(0.2)
    print(f"    after freeing slot 0: c4.got_echo={c4.got_echo} "
          f"(expect True now)")
    recovered_correctly = c4.got_echo

    client_sampler.sample()
    server_sampler.sample()
    print(f"    client fds={client_sampler.history[-1]['fds']} "
          f"rss_kb={client_sampler.history[-1]['rss_kb']} | "
          f"server fds={server_sampler.history[-1]['fds']} "
          f"rss_kb={server_sampler.history[-1]['rss_kb']}")

    for c in conns + [c4]:
        if not c.release_event.is_set():
            c.release()
    time.sleep(0.5)
    final_alive = client_proc.poll() is None and server_proc.poll() is None

    for p in (client_proc, server_proc, target_proc):
        try:
            p.kill()
        except Exception:
            pass

    ok = dry_queued and recovered_correctly and final_alive
    print(f"=== [{tag}] VERDICT: {'PASS' if ok else 'FAIL'} ===", flush=True)
    return ok


def main():
    log_dir = "/tmp/quictun_chaos_logs"
    os.makedirs(log_dir, exist_ok=True)

    results = {}
    print("=== SCENARIO: removal (pooled connections' shared path dies, "
          "auto-rebuild on next request) ===", flush=True)
    results["removal"] = scenario_removal(log_dir)

    print("\n=== SCENARIO: allocation (round-robin genuinely spreads "
          "across all slots) ===", flush=True)
    results["allocation"] = scenario_allocation(log_dir)

    print("\n=== SCENARIO: dry_queue (new request can land on a full "
          "slot while another has room) ===", flush=True)
    results["dry_queue"] = scenario_dry_queue(log_dir)

    print("\n=== SUMMARY ===")
    overall_ok = True
    for name, ok in results.items():
        print(f"  {name}: {'PASS' if ok else 'FAIL'}")
        overall_ok = overall_ok and ok
    print(f"=== pool_lifecycle_test VERDICT: {'PASS' if overall_ok else 'FAIL'} ===",
          flush=True)
    sys.exit(0 if overall_ok else 1)


if __name__ == "__main__":
    main()
