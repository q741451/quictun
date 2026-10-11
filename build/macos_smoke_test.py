#!/usr/bin/env python3
"""Runtime smoke test for a quictun_client/quictun_server pair on a host
where nothing else runs them (macOS in CI). Standard library only.

  1. Data: several tunnels at once, each echoing 4 MiB of random bytes
     through client -> QUIC -> server -> TCP echo target and back, compared
     by SHA-256. Then the same over IPv6 (::1), and an IPv4 client against a
     dual-stack [::] server.
  2. Unreachable --target: a tunnel whose server-side connect is refused
     must be closed promptly, not hang, and the server must not spin while
     it happens (this is where a poll() event the loop does not understand
     would show).
  3. Refusals: flags this OS cannot honour must exit non-zero at startup,
     and --transparent must still start on the server, which supports it.
  4. A second quictun_server on the same port must fail, not share it.

Usage: macos_smoke_test.py <quictun_client> <quictun_server>
"""
import hashlib
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

CLIENT, SERVER = (os.path.abspath(p) for p in sys.argv[1:3])
KEY = "macos-smoke-key"
LOGDIR = tempfile.mkdtemp(prefix="quictun-smoke-")
procs = []


def free_port(kind=socket.SOCK_STREAM, family=socket.AF_INET):
    s = socket.socket(family, kind)
    s.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start(name, args):
    log = open(os.path.join(LOGDIR, name + ".log"), "w")
    p = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
    procs.append((name, p))
    return p


def dump_logs():
    for name in sorted(os.listdir(LOGDIR)):
        print(f"----- {name} -----")
        with open(os.path.join(LOGDIR, name)) as f:
            print(f.read()[-4000:])


def fail(msg):
    print("FAIL:", msg)
    dump_logs()
    sys.exit(1)


def wait_listening(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.1)
    fail(f"nothing listening on {port} after {timeout}s")


def echo_server(port):
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", port))
    ls.listen(64)

    def serve(c):
        with c:
            while True:
                b = c.recv(65536)
                if not b:
                    c.shutdown(socket.SHUT_WR)
                    return
                c.sendall(b)

    def loop():
        while True:
            c, _ = ls.accept()
            threading.Thread(target=serve, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()


def check_data(what, local, n, size):
    results = [None] * n
    t0 = time.time()
    threads = [threading.Thread(target=one_tunnel,
                                args=(local, size, results, i))
               for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(120)
    if results != ["ok"] * n:
        fail(f"{what}: {results}")
    print(f"ok: {what}: {n} x {size} bytes echoed intact in "
          f"{time.time() - t0:.1f}s")


def one_tunnel(port, size, results, i):
    data = os.urandom(size)
    got = bytearray()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=60)
        s.settimeout(60)

        # Read until the whole echo is back, and only then close: quictun
        # has no TCP half-close (an EOF from either side tears the tunnel
        # down once what was sent before it is delivered), so shutting down
        # the write side early would cut off the echo still in flight.
        def reader():
            while len(got) < size:
                b = s.recv(65536)
                if not b:
                    return
                got.extend(b)

        t = threading.Thread(target=reader)
        t.start()
        s.sendall(data)
        t.join(90)
        s.close()
    except OSError as e:
        results[i] = f"error {e!r} after {len(got)} bytes"
        return
    if hashlib.sha256(got).digest() != hashlib.sha256(data).digest():
        results[i] = f"mismatch: sent {len(data)}, got {len(got)}"
    else:
        results[i] = "ok"


def cpu_seconds(pid):
    """Total CPU time of `pid` so far, from ps (no psutil on the runner)."""
    out = subprocess.run(["ps", "-o", "time=", "-p", str(pid)],
                         capture_output=True, text=True).stdout.strip()
    total = 0.0
    for part in out.replace("-", ":").split(":"):
        total = total * 60 + float(part)
    return total


def run(args, timeout):
    """(exit code, output), or (None, output) if still running at timeout."""
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, r.stdout + r.stderr
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"") + (e.stderr or b"")
        return None, out.decode(errors="replace")


def must_refuse(name, args, needle):
    rc, out = run(args, 10)
    if rc is None or rc == 0 or needle not in out:
        fail(f"{name}: expected a non-zero exit mentioning {needle!r}, "
             f"got {rc}: {out[-2000:]}")
    print(f"ok: {name} refused (exit {rc}): {needle}")


def main():
    try:
        target = free_port()
        listen = free_port(socket.SOCK_DGRAM)
        local = free_port()
        echo_server(target)

        start("server", [SERVER, f"--listen=127.0.0.1:{listen}",
                         f"--target=127.0.0.1:{target}", f"--key={KEY}"])
        start("client", [CLIENT, f"--local=127.0.0.1:{local}",
                         f"--remote=127.0.0.1:{listen}", f"--key={KEY}"])
        wait_listening(local)

        # 1. Data.
        check_data("IPv4", local, 4, 4 * 1024 * 1024)

        # IPv6 end to end: the client's socket is connected to ::1, so its
        # writer must see the peer exactly as it connected to it.
        listen6 = free_port(socket.SOCK_DGRAM, socket.AF_INET6)
        local6 = free_port()
        start("server-v6", [SERVER, f"--listen=[::1]:{listen6}",
                            f"--target=127.0.0.1:{target}", f"--key={KEY}"])
        start("client-v6", [CLIENT, f"--local=127.0.0.1:{local6}",
                            f"--remote=[::1]:{listen6}", f"--key={KEY}"])
        wait_listening(local6)
        check_data("IPv6", local6, 2, 1024 * 1024)

        # Dual stack: an IPv4 client against a server listening on [::],
        # which sees it as ::ffff:127.0.0.1 and must answer it there.
        listen46 = free_port(socket.SOCK_DGRAM)
        local46 = free_port()
        start("server-dual", [SERVER, f"--listen=[::]:{listen46}",
                              f"--target=127.0.0.1:{target}", f"--key={KEY}"])
        start("client-dual", [CLIENT, f"--local=127.0.0.1:{local46}",
                              f"--remote=127.0.0.1:{listen46}",
                              f"--key={KEY}"])
        wait_listening(local46)
        check_data("IPv4 to dual-stack [::]", local46, 2, 1024 * 1024)

        # 2. Unreachable --target: nothing listens on `closed`.
        closed = free_port()
        listen2 = free_port(socket.SOCK_DGRAM)
        local2 = free_port()
        server_unreach = start("server-unreach",
                               [SERVER, f"--listen=127.0.0.1:{listen2}",
                                f"--target=127.0.0.1:{closed}",
                                f"--key={KEY}"])
        start("client-unreach", [CLIENT, f"--local=127.0.0.1:{local2}",
                                 f"--remote=127.0.0.1:{listen2}",
                                 f"--key={KEY}"])
        wait_listening(local2)
        s = socket.create_connection(("127.0.0.1", local2), timeout=5)
        s.settimeout(15)
        t0 = time.time()
        try:
            s.sendall(b"hello")
            b = s.recv(1)
        except OSError:
            b = b""
        if b:
            fail("unreachable target: got data back")
        elapsed = time.time() - t0
        if elapsed > 10:
            fail(f"unreachable target: tunnel took {elapsed:.1f}s to close")
        print(f"ok: unreachable --target closed the tunnel in {elapsed:.2f}s")
        # And left nothing spinning: an idle server burns next to no CPU.
        before = cpu_seconds(server_unreach.pid)
        time.sleep(3)
        burned = cpu_seconds(server_unreach.pid) - before
        if burned > 0.5:
            fail(f"unreachable target: server used {burned:.2f}s of CPU "
                 f"in 3s idle afterwards")
        print(f"ok: server idle afterwards ({burned:.2f}s CPU in 3s)")

        # 3. Refusals.
        must_refuse("client --udp_gso",
                    [CLIENT, f"--local=127.0.0.1:{free_port()}",
                     f"--remote=127.0.0.1:{listen}", f"--key={KEY}",
                     "--udp_gso"], "--udp_gso is only available on Linux")
        must_refuse("client --transparent",
                    [CLIENT, f"--local=127.0.0.1:{free_port()}",
                     f"--remote=127.0.0.1:{listen}", f"--key={KEY}",
                     "--transparent"], "--transparent is only available")
        must_refuse("server --udp_gso",
                    [SERVER, f"--listen=127.0.0.1:{free_port(socket.SOCK_DGRAM)}",
                     f"--target=127.0.0.1:{target}", f"--key={KEY}",
                     "--udp_gso"], "--udp_gso is only available on Linux")
        p = start("server-transparent",
                  [SERVER, f"--listen=127.0.0.1:{free_port(socket.SOCK_DGRAM)}",
                   f"--key={KEY}", "--transparent"])
        time.sleep(2)
        if p.poll() is not None:
            fail(f"server --transparent exited ({p.returncode}); it should run")
        print("ok: server --transparent starts")

        # 4. Second server on a port already in use.
        rc, out = run([SERVER, f"--listen=127.0.0.1:{listen}",
                       f"--target=127.0.0.1:{target}", f"--key={KEY}"], 10)
        if rc is None or rc == 0:
            fail(f"second server on the same port did not fail ({rc}): "
                 f"{out[-2000:]}")
        print(f"ok: second server on port {listen} refused (exit {rc})")

        for name, p in procs:
            if p.poll() is not None:
                fail(f"{name} died early with {p.returncode}")
        print("PASS")
    finally:
        for _, p in procs:
            if p.poll() is None:
                p.kill()


main()
