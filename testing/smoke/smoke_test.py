#!/usr/bin/env python3
"""Smoke test for built quictun_client/quictun_server binaries, on any OS.

    smoke_test.py <directory holding quictun_server-* and quictun_client-*>

Runs the binaries as subprocesses on loopback against local TCP services and
checks that data gets through, and that no case leaves either process
spinning: a case passes the CPU check when neither process used more than
20% of a core over the 5s after it. Each case gets a fresh server/client
pair, so one case's spinning cannot show up as the next one's.

The cases are the ones that differ between Linux, macOS and Windows, or that
once pinned a core:

  idle / traffic           baseline: idle, 8 MB echo, 10 concurrent streams
  refused target           the tunneled connection is closed, not left open
  local half-close         the app shuts down sending and stops reading while
                           the echo backs up: WSAPoll() reports POLLHUP from
                           the peer's FIN on, requested or not
  backpressure             the app sends without reading until every buffer
                           on the way is full, then reads: nothing spins
                           while stuck, and every byte comes back
  urgent byte              TCP out-of-band data: WSAPoll()'s POLLIN includes
                           POLLRDBAND, which recv() never consumes
  local reset              the app resets mid-transfer
  response tail            the target sends 8 MB and closes at once, the app
                           reads late and slowly: every byte must arrive
  400 connections          above macOS's default of 256 open files
  out of descriptors       (not Windows) client limited to 64 descriptors and
                           offered 100 connections: accept() keeps failing
                           with EMFILE, which must neither spin nor go unlogged
  dual stack               a [::] server reached over IPv4 and IPv6, and a
                           [::] --local: Windows reports an IPv4 packet's
                           destination only when asked for IPv4 packet info
  many UDP sockets         --udp_socket=3 --conn_per_udp=2
  non-ASCII key            --key reaches quictun as its UTF-8 bytes, which
                           Windows' main() argv does not deliver
  large socket buffer      --udp_socket_buffer_kb past the system's limit
                           runs or fails at startup, never half works
  server gone / restarted  ICMP port unreachable on the client's UDP socket,
                           then recovery
  client restarted         rebinding --local while old connections linger

Exits non-zero if any check failed. Server and client logs are kept in a
temporary directory, printed at the end; their E/F lines are shown inline.
"""

import ctypes
import glob
import os
import random
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

WINDOWS = sys.platform == "win32"
KEY = "--key=smoke test key"
# Below 32768 on purpose: Linux hands out ephemeral ports from 32768-60999
# (macOS and Windows from 49152), and this script's own hundreds of
# connections would otherwise sometimes hold a port a later case binds.
ECHO_PORT, REFUSED_PORT, TAIL_PORT = 24000, 24001, 24002
UDP_BASE, LOCAL_BASE = 24100, 24200
CPU_LIMIT_PERCENT = 20

failures = []


def check(ok, what):
    print(("PASS " if ok else "FAIL ") + what, flush=True)
    if not ok:
        failures.append(what)


# --- CPU seconds (user + system) a child process has used so far ---

if WINDOWS:
    class FILETIME(ctypes.Structure):
        _fields_ = [("lo", ctypes.c_uint32), ("hi", ctypes.c_uint32)]

    kernel32 = ctypes.WinDLL("kernel32")

    def cpu_seconds(proc):
        c, e, k, u = FILETIME(), FILETIME(), FILETIME(), FILETIME()
        kernel32.GetProcessTimes(ctypes.c_void_p(int(proc._handle)), ctypes.byref(c),
                                 ctypes.byref(e), ctypes.byref(k), ctypes.byref(u))
        return ((k.hi << 32 | k.lo) + (u.hi << 32 | u.lo)) / 1e7
elif sys.platform == "linux":
    def cpu_seconds(proc):
        fields = open(f"/proc/{proc.pid}/stat").read().rsplit(")", 1)[1].split()
        return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
else:
    def cpu_seconds(proc):
        out = subprocess.run(["ps", "-o", "cputime=", "-p", str(proc.pid)],
                             capture_output=True, text=True).stdout.strip()
        seconds = 0.0
        for part in out.split(":"):
            seconds = seconds * 60 + float(part)
        return seconds


def check_no_spin(what, procs, seconds=5):
    """Checks that no process in `procs` used more than CPU_LIMIT_PERCENT of
    a core over the next `seconds` -- and that each is still running, since
    one that died (say of a SIGPIPE) would pass the CPU check by using none."""
    before = [cpu_seconds(p) for p in procs]
    time.sleep(seconds)
    used = [cpu_seconds(p) - b for p, b in zip(procs, before)]
    percent = max(used) / seconds * 100
    print(f"cpu {what}: " + ", ".join(f"{u:.2f}s" for u in used) +
          f" over {seconds}s", flush=True)
    check(percent < CPU_LIMIT_PERCENT, f"no busy loop: {what} ({percent:.0f}%)")
    exited = [p.returncode for p in procs if p.poll() is not None]
    check(not exited, f"still running: {what}" +
          (f" (exited with {exited})" if exited else ""))


# --- local TCP services the server tunnels to ---

def serve_forever(port, handler):
    listener = socket.create_server(("127.0.0.1", port))

    def accept():
        while True:
            conn, _ = listener.accept()
            threading.Thread(target=handler, args=(conn,), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()


def echo(conn):
    with conn:
        try:
            while data := conn.recv(65536):
                conn.sendall(data)
        except OSError:
            pass


TAIL = random.Random(1).getrandbits(8 << 23).to_bytes(8 << 20, "little")


def send_tail_then_close(conn):
    # An HTTP/1.0-style server: writes the whole response and closes at once.
    with conn:
        try:
            conn.sendall(TAIL)
        except OSError:
            pass


# --- server/client pairs ---

class Binaries:
    def __init__(self, directory):
        self.server = glob.glob(os.path.join(directory, "quictun_server-*"))[0]
        self.client = glob.glob(os.path.join(directory, "quictun_client-*"))[0]
        for path in (self.server, self.client):
            os.chmod(path, 0o755)


class Harness:
    def __init__(self, binaries, log_dir):
        self.bin = binaries
        self.log_dir = log_dir
        self.procs = []
        self.pairs = 0

    def start(self, args, log_name, nofile=None):
        preexec = None
        if nofile is not None:
            import resource
            soft, hard = nofile

            def preexec():
                resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
        log = os.path.join(self.log_dir, log_name)
        # Its own process group on Windows, so stop() can send it
        # CTRL_BREAK_EVENT without hitting this script too.
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if WINDOWS else 0
        proc = subprocess.Popen(args, stdout=open(log, "w"),
                                stderr=subprocess.STDOUT, preexec_fn=preexec,
                                creationflags=flags)
        self.procs.append((proc, log))
        return proc

    def start_server(self, udp_port, target_port, log_name):
        return self.start([self.bin.server, f"--listen=127.0.0.1:{udp_port}",
                           f"--target=127.0.0.1:{target_port}", KEY], log_name)

    def start_client(self, local_port, udp_port, log_name, nofile=None):
        return self.start([self.bin.client, f"--local=127.0.0.1:{local_port}",
                           f"--remote=127.0.0.1:{udp_port}", KEY], log_name,
                          nofile=nofile)

    def pair(self, target_port, client_nofile=None):
        """A fresh server and client; returns (server, client, local port,
        udp port, client log)."""
        n = self.pairs
        self.pairs += 1
        udp, local = UDP_BASE + n, LOCAL_BASE + n
        server = self.start_server(udp, target_port, f"server{n}.log")
        client = self.start_client(local, udp, f"client{n}.log", client_nofile)
        time.sleep(2)
        return server, client, local, udp, os.path.join(self.log_dir, f"client{n}.log")

    @staticmethod
    def stop(*procs):
        """Asks each process to exit (SIGTERM, or CTRL_BREAK_EVENT on
        Windows), then kills whatever is still running 3s later. A normal
        build just dies of either; a coverage build (QUICTUN_COVERAGE_BUILD)
        writes its profile first, which a kill would lose."""
        for proc in procs:
            if proc.poll() is None:
                try:
                    if WINDOWS:
                        proc.send_signal(signal.CTRL_BREAK_EVENT)
                    else:
                        proc.terminate()
                except OSError:
                    pass
        for proc in procs:
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def report_logs(self):
        for proc, log in self.procs:
            self.stop(proc)
            lines = [line for line in open(log).read().splitlines()
                     if line[:1] in ("E", "F")]
            if lines:
                print(f"--- {os.path.basename(log)}: {len(lines)} E/F lines ---")
                print("\n".join(lines[:12]))
        print(f"logs: {self.log_dir}")


def roundtrip(local, payload, timeout=20):
    """Sends `payload` through the tunnel to the echo service and reads it
    back; returns whether it came back intact."""
    try:
        conn = socket.create_connection(("127.0.0.1", local), timeout=timeout)
        conn.sendall(payload)
        got = b""
        while len(got) < len(payload) and (data := conn.recv(65536)):
            got += data
        conn.close()
        return got == payload
    except OSError as e:
        print(f"roundtrip: {e!r}")
        return False


# --- cases ---

def case_idle_and_traffic(h):
    server, client, local, _, _ = h.pair(ECHO_PORT)
    check_no_spin("idle", [server, client])
    data = os.urandom(8 << 20)
    got = bytearray()
    conn = socket.create_connection(("127.0.0.1", local), timeout=30)

    def reader():
        while len(got) < len(data) and (chunk := conn.recv(65536)):
            got.extend(chunk)

    t = threading.Thread(target=reader)
    t.start()
    conn.sendall(data)
    t.join(60)
    conn.close()
    check(bytes(got) == data, f"8 MB echo intact ({len(got)} bytes)")

    results = {}

    def one(i):
        payload = os.urandom(1 << 20)
        try:
            c = socket.create_connection(("127.0.0.1", local), timeout=30)
            writer = threading.Thread(target=c.sendall, args=(payload,))
            writer.start()
            back = bytearray()
            while len(back) < len(payload) and (chunk := c.recv(65536)):
                back.extend(chunk)
            writer.join()
            c.close()
            results[i] = back == payload
        except OSError as e:
            results[i] = repr(e)

    threads = [threading.Thread(target=one, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(90)
    check(len(results) == 10 and all(v is True for v in results.values()),
          f"10 concurrent 1 MB streams: {results}")
    check_no_spin("idle after traffic", [server, client])
    h.stop(server, client)


def case_refused_target(h):
    server, client, local, _, _ = h.pair(REFUSED_PORT)
    try:
        conn = socket.create_connection(("127.0.0.1", local), timeout=15)
        conn.sendall(b"hello")
        try:
            closed = conn.recv(10) == b""
        except (ConnectionResetError, ConnectionAbortedError):
            closed = True
        conn.close()
        check(closed, "refused target closes the tunneled connection")
    except OSError as e:
        check(False, f"refused target: {e!r}")
    check_no_spin("after a refused target", [server, client])
    h.stop(server, client)


def case_local_half_close(h):
    server, client, local, _, _ = h.pair(ECHO_PORT)
    conn = socket.create_connection(("127.0.0.1", local), timeout=10)
    conn.setblocking(False)
    deadline = time.time() + 3
    while time.time() < deadline:
        try:
            conn.send(b"h" * 65536)
        except BlockingIOError:
            time.sleep(0.01)
    conn.shutdown(socket.SHUT_WR)
    check_no_spin("local app shut down sending, echo backed up", [server, client])
    conn.close()
    h.stop(server, client)


def case_backpressure_recovers(h):
    # The app sends without reading until the echo has backed up through
    # every buffer on the way -- its own socket, the client, QUIC flow
    # control, the server, the echo service -- then reads: every byte must
    # come back, and nothing may spin while it is all stuck.
    server, client, local, _, _ = h.pair(ECHO_PORT)
    conn = socket.create_connection(("127.0.0.1", local), timeout=10)
    sent = send_until_full(conn, 64 << 20)
    check_no_spin(f"everything backed up ({len(sent)} bytes in flight)",
                  [server, client])
    conn.setblocking(True)
    conn.settimeout(30)
    got = bytearray()
    try:
        while len(got) < len(sent) and (data := conn.recv(65536)):
            got.extend(data)
    except OSError as e:
        print(f"backpressure: {e!r}")
    conn.close()
    check(bytes(got) == sent,
          f"echo resumes once the app reads ({len(got)} of {len(sent)} bytes)")
    h.stop(server, client)


def case_urgent_byte(h):
    server, client, local, _, _ = h.pair(ECHO_PORT)
    conn = socket.create_connection(("127.0.0.1", local), timeout=10)
    conn.send(b"AB")
    time.sleep(0.1)
    conn.send(b"U", socket.MSG_OOB)
    time.sleep(0.1)
    conn.send(b"CD")
    check_no_spin("urgent byte from the local app", [server, client])
    conn.settimeout(5)
    got = b""
    try:
        while len(got) < 4 and (data := conn.recv(100)):
            got += data
    except OSError:
        pass
    # As on Linux without SO_OOBINLINE: the urgent byte is not part of the
    # stream, the data around it is.
    check(got == b"ABCD", f"data around an urgent byte arrives ({got!r})")
    conn.close()
    h.stop(server, client)


def send_until_full(conn, limit, give_up_after=1.0):
    """Sends random data on non-blocking `conn` until `limit` bytes are out or
    nothing more has fit for `give_up_after` seconds; returns what was sent.
    How much fits depends on every buffer along the way, which differs by OS
    and grows with load (macOS autotunes), so cases must not assume it."""
    conn.setblocking(False)
    sent = bytearray()
    stuck_since = None
    while len(sent) < limit:
        chunk = os.urandom(min(65536, limit - len(sent)))
        try:
            n = conn.send(chunk)
            sent += chunk[:n]
            stuck_since = None
        except BlockingIOError:
            stuck_since = stuck_since or time.time()
            if time.time() - stuck_since > give_up_after:
                break
            time.sleep(0.01)
    return bytes(sent)


def case_local_reset(h):
    server, client, local, _, _ = h.pair(ECHO_PORT)
    conn = socket.create_connection(("127.0.0.1", local), timeout=10)
    send_until_full(conn, 4 << 20)
    # SO_LINGER with a zero timeout: close() sends RST.
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                    struct.pack("HH" if WINDOWS else "ii", 1, 0))
    conn.close()
    check_no_spin("local app reset mid-transfer", [server, client])
    h.stop(server, client)


def case_response_tail(h):
    server, client, local, _, _ = h.pair(TAIL_PORT)
    conn = socket.create_connection(("127.0.0.1", local), timeout=60)
    time.sleep(5)  # longer than the tunnel's 3s flush-close wait
    got = bytearray()
    try:
        while data := conn.recv(65536):
            got.extend(data)
            time.sleep(0.002)  # a slow reader
    except OSError as e:
        print(f"response tail: {e!r}")
    conn.close()
    check(bytes(got) == TAIL,
          f"response tail intact after the target closed ({len(got)} of {len(TAIL)} bytes)")
    check_no_spin("after the target closed", [server, client])
    h.stop(server, client)


def case_many_connections(h):
    nofile = None
    if sys.platform == "darwin":
        # macOS starts processes at 256 open files, but GitHub's runners
        # raise that to 10240: give the client the system default back, so
        # only RaiseOpenFileLimit() gets it past 256.
        import resource
        nofile = (256, resource.getrlimit(resource.RLIMIT_NOFILE)[1])
    server, client, local, _, _ = h.pair(ECHO_PORT, client_nofile=nofile)
    conns, refused = [], 0
    for i in range(400):
        try:
            c = socket.create_connection(("127.0.0.1", local), timeout=10)
            c.sendall(b"m%03d" % i)
            conns.append(c)
        except OSError:
            refused += 1
    echoed = 0
    for i, c in enumerate(conns):
        try:
            c.settimeout(20)
            if c.recv(10) == b"m%03d" % i:
                echoed += 1
        except OSError:
            pass
    check(refused == 0 and echoed == 400,
          f"400 concurrent connections all echo ({echoed} echoed, {refused} refused)")
    for c in conns:
        c.close()
    check_no_spin("after 400 connections closed", [server, client])
    h.stop(server, client)


def case_out_of_descriptors(h):
    server, client, local, _, client_log = h.pair(ECHO_PORT, client_nofile=(64, 64))
    held = []
    for _ in range(100):
        try:
            held.append(socket.create_connection(("127.0.0.1", local), timeout=2))
        except OSError:
            break
    check_no_spin(f"client out of descriptors ({len(held)} connections offered)",
                  [server, client])
    for c in held:
        c.close()
    time.sleep(2)
    check(roundtrip(local, b"after running out"),
          "client accepts again once descriptors are free")
    check(client.poll() is None, "client still running after running out of descriptors")
    h.stop(server, client)
    check("Accept() failed" in open(client_log).read(),
          "client logged running out of descriptors")


def case_dual_stack(h):
    # --listen=[::] is README's own example: an IPv6 socket that IPv4 clients
    # reach as ::ffff:a.b.c.d, which macOS and Windows hand over with their
    # own packet-info and address-family rules. A client on IPv4 and one on
    # IPv6 against the one server, and a client whose --local is [::] too,
    # reached over both families.
    n = h.pairs
    h.pairs += 1
    udp, local4, local6 = UDP_BASE + n, LOCAL_BASE + n, LOCAL_BASE + 50 + n
    server = h.start([h.bin.server, f"--listen=[::]:{udp}",
                      f"--target=127.0.0.1:{ECHO_PORT}", KEY], f"server{n}.log")
    client4 = h.start([h.bin.client, f"--local=127.0.0.1:{local4}",
                       f"--remote=127.0.0.1:{udp}", KEY], f"client{n}_v4.log")
    client6 = h.start([h.bin.client, f"--local=[::]:{local6}",
                       f"--remote=[::1]:{udp}", KEY], f"client{n}_v6.log")
    time.sleep(2)
    check(roundtrip(local4, os.urandom(1 << 20)),
          "IPv4 client through a dual-stack [::] server")
    check(roundtrip(local6, os.urandom(1 << 20)),
          "IPv6 client through a dual-stack [::] server, app over IPv4")
    try:
        conn = socket.create_connection(("::1", local6), timeout=20)
        payload = os.urandom(1 << 20)
        conn.sendall(payload)
        got = b""
        while len(got) < len(payload) and (data := conn.recv(65536)):
            got += data
        conn.close()
        check(got == payload, "IPv6 client, app over IPv6 to a [::] --local")
    except OSError as e:
        check(False, f"app over IPv6 to a [::] --local: {e!r}")
    check_no_spin("dual-stack server, IPv4 and IPv6 clients",
                  [server, client4, client6])
    h.stop(server, client4, client6)


def case_many_udp_sockets(h):
    # --udp_socket x --conn_per_udp: several connected UDP sockets, each
    # carrying several QUIC connections, round-robin.
    n = h.pairs
    h.pairs += 1
    udp, local = UDP_BASE + n, LOCAL_BASE + n
    server = h.start_server(udp, ECHO_PORT, f"server{n}.log")
    client = h.start([h.bin.client, f"--local=127.0.0.1:{local}",
                      f"--remote=127.0.0.1:{udp}", "--udp_socket=3",
                      "--conn_per_udp=2", KEY], f"client{n}.log")
    time.sleep(2)
    results = []

    def one():
        results.append(roundtrip(local, os.urandom(256 << 10)))

    threads = [threading.Thread(target=one) for _ in range(24)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(90)
    check(len(results) == 24 and all(results),
          f"24 connections over 3 UDP sockets x 2 connections ({sum(results)} ok)")
    check_no_spin("3 UDP sockets x 2 connections", [server, client])
    h.stop(server, client)


def case_non_ascii_key(h):
    # --key's bytes are what both ends derive their keys from, so a client
    # and a server on different systems agree only if each reads the same
    # bytes from the same characters: UTF-8. Linux and macOS hand main() the
    # bytes as given; Windows converts the command line to its ANSI code
    # page first. The banner reports the key's length in bytes.
    key = "quictun 共享密钥 ✓"
    want = len(key.encode("utf-8"))
    n = h.pairs
    h.pairs += 1
    server = h.start([h.bin.server, f"--listen=127.0.0.1:{UDP_BASE + n}",
                      f"--target=127.0.0.1:{ECHO_PORT}", f"--key={key}"],
                     f"server{n}.log")
    time.sleep(2)
    h.stop(server)
    banner = open(os.path.join(h.log_dir, f"server{n}.log"), "rb").read()
    m = re.search(rb"key\s*=\s*<redacted, (\d+) bytes>", banner)
    got = int(m.group(1)) if m else None
    check(got == want, f"a non-ASCII --key reaches quictun as its UTF-8 bytes "
                       f"({got} bytes, UTF-8 is {want})")


def case_large_socket_buffer(h):
    # --udp_socket_buffer_kb past what the system allows: Linux clamps it
    # silently (README), macOS caps SO_RCVBUF at kern.ipc.maxsockbuf. Either
    # the binaries run, or they stop at startup saying why -- never a socket
    # that half works.
    n = h.pairs
    h.pairs += 1
    server = h.start([h.bin.server, f"--listen=127.0.0.1:{UDP_BASE + n}",
                      f"--target=127.0.0.1:{ECHO_PORT}",
                      "--udp_socket_buffer_kb=65536", KEY], f"server{n}.log")
    client = h.start([h.bin.client, f"--local=127.0.0.1:{LOCAL_BASE + n}",
                      f"--remote=127.0.0.1:{UDP_BASE + n}",
                      "--udp_socket_buffer_kb=65536", KEY], f"client{n}.log")
    time.sleep(2)
    outcome = []
    for proc, name in ((server, "server"), (client, "client")):
        if proc.poll() is None:
            outcome.append(f"{name} running")
        else:
            log = open(os.path.join(h.log_dir, f"{name}{n}.log"),
                       errors="replace").read().splitlines()
            reason = [l for l in log if "size" in l or "Failed" in l][:1]
            outcome.append(f"{name} exited {proc.returncode}: {reason}")
    if server.poll() is None and client.poll() is None:
        ok = roundtrip(LOCAL_BASE + n, b"big buffers")
    else:
        ok = all(p.poll() is None or p.returncode != 0 for p in (server, client))
    check(ok, f"a socket buffer past the system's limit runs or fails "
              f"loudly ({outcome})")
    h.stop(server, client)


def case_server_gone_then_client_restarted(h):
    server, client, local, udp, _ = h.pair(ECHO_PORT)
    h.stop(server)
    try:
        conn = socket.create_connection(("127.0.0.1", local), timeout=10)
        conn.sendall(b"x" * 1000)
        conn.settimeout(3)
        try:
            conn.recv(10)
        except OSError:
            pass
        conn.close()
    except OSError as e:
        print(f"server gone: {e!r}")
    check_no_spin("server gone (ICMP port unreachable)", [client])
    check(client.poll() is None, "client survives the server going away")

    server = h.start_server(udp, ECHO_PORT, "server_restarted.log")
    time.sleep(2)
    # The client's old connection has to be found dead first.
    ok = False
    for _ in range(6):
        if roundtrip(local, b"after server restart"):
            ok = True
            break
        time.sleep(5)
    check(ok, "client tunnels again after the server restarts")

    held = []
    for _ in range(3):
        c = socket.create_connection(("127.0.0.1", local), timeout=20)
        c.sendall(b"held")
        c.recv(10)
        held.append(c)
    held[0].setblocking(False)
    try:
        held[0].send(b"y" * (4 << 20))  # one with data still in flight
    except BlockingIOError:
        pass
    h.stop(client)
    client = h.start_client(local, udp, "client_restarted.log")
    time.sleep(2)
    check(client.poll() is None, "restarted client is running")
    check(roundtrip(local, b"after client restart"),
          "restarted client tunnels on the same --local port")
    for c in held:
        c.close()
    h.stop(server, client)


def main():
    binaries = Binaries(sys.argv[1] if len(sys.argv) > 1 else ".")
    h = Harness(binaries, tempfile.mkdtemp(prefix="quictun-smoke-"))
    print(f"{sys.platform}: {os.path.basename(binaries.server)}, "
          f"{os.path.basename(binaries.client)}", flush=True)
    for exe in (binaries.server, binaries.client):
        r = subprocess.run([exe, "--helpfull"], capture_output=True, text=True, timeout=30)
        check("--key" in r.stdout + r.stderr, f"{os.path.basename(exe)} --helpfull")

    serve_forever(ECHO_PORT, echo)
    serve_forever(TAIL_PORT, send_tail_then_close)

    cases = [
        case_idle_and_traffic,
        case_refused_target,
        case_local_half_close,
        case_backpressure_recovers,
        case_urgent_byte,
        case_local_reset,
        case_response_tail,
        case_many_connections,
        case_dual_stack,
        case_many_udp_sockets,
        case_non_ascii_key,
        case_large_socket_buffer,
    ]
    if not WINDOWS:  # Windows has no per-process descriptor limit to lower
        cases.append(case_out_of_descriptors)
    cases.append(case_server_gone_then_client_restarted)
    for case in cases:
        try:
            case(h)
        except Exception as e:  # one broken case must not hide the rest
            check(False, f"{case.__name__} raised {e!r}")
            for proc, _ in h.procs:
                h.stop(proc)

    h.report_logs()
    print("FAILURES:", failures if failures else "none")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
