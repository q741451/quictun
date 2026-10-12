#!/usr/bin/env python3
"""What a laptop's sleep and its clock corrections do to a running tunnel.

    clock_test.py <directory holding quictun_server-* and quictun_client-*>

Changes the system clock, so it needs root (sudo on Linux and macOS, an
elevated shell on Windows) and is meant for CI runners: Build's "clock"
checkbox runs it. Not part of smoke_test.py for that reason.

quictun's QUIC timers run on the wall clock (QuicDefaultClock). Cases:

  client asleep            the client frozen past both idle timeouts, the
                           server left running: the lid of a laptop closed
  clock +2h                the clock jumps ahead, as it does across a sleep
  clock -2s                a small step back, as a time sync after waking
  clock -10min             a large step back

Each case reports what happens to a tunnel opened before the event (closed,
or answering after how long) and how soon a new tunnel works; the CPU and
liveness checks are the ones smoke_test.py applies. The idle timeout is cut
to 10s (default 60s) to keep the run short. Every case stops its processes
before putting the clock back, since that is a jump of its own.
"""

import ctypes
import os
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import smoke_test as s  # noqa: E402

IDLE = "--idle_timeout_seconds=10"
UDP_BASE, LOCAL_BASE = 24300, 24400


# --- the system clock ---

def set_clock_by(seconds):
    """Steps the system clock by `seconds` (either sign), at once."""
    target = time.time() + seconds
    if s.WINDOWS:
        subprocess.run(["powershell", "-NoProfile", "-Command",
                        f"Set-Date -Adjust ([TimeSpan]::FromSeconds({seconds}))"],
                       check=True, capture_output=True)
    elif sys.platform == "darwin":
        stamp = time.strftime("%m%d%H%M%Y.%S", time.gmtime(target))
        subprocess.run(["sudo", "date", "-u", stamp], check=True,
                       capture_output=True)
    else:
        subprocess.run(["sudo", "date", "-u", "-s", f"@{target:.3f}"],
                       check=True, capture_output=True)
    print(f"clock stepped by {seconds:+}s", flush=True)


def stop_time_sync():
    """Keeps the OS from undoing the steps while the cases run."""
    if s.WINDOWS:
        subprocess.run(["net", "stop", "w32time"], capture_output=True)
    elif sys.platform == "darwin":
        subprocess.run(["sudo", "systemsetup", "-setusingnetworktime", "off"],
                       capture_output=True)
    else:
        subprocess.run(["sudo", "timedatectl", "set-ntp", "false"],
                       capture_output=True)


# --- freezing a process, as sleep does ---

if s.WINDOWS:
    ntdll = ctypes.WinDLL("ntdll")

    def freeze(proc):
        ntdll.NtSuspendProcess(ctypes.c_void_p(int(proc._handle)))

    def thaw(proc):
        ntdll.NtResumeProcess(ctypes.c_void_p(int(proc._handle)))
else:
    import signal

    def freeze(proc):
        os.kill(proc.pid, signal.SIGSTOP)

    def thaw(proc):
        os.kill(proc.pid, signal.SIGCONT)


# --- probes ---

class Tunnel:
    """One long-lived tunneled connection to the echo service."""

    def __init__(self, local):
        self.conn = socket.create_connection(("127.0.0.1", local), timeout=10)

    def ping(self, timeout):
        """Seconds until an 8-byte echo came back; None if the tunnel closed
        or errored, float('inf') if nothing came back within `timeout`."""
        self.conn.settimeout(timeout)
        start = time.monotonic()
        try:
            self.conn.sendall(b"ping1234")
            got = b""
            while len(got) < 8:
                data = self.conn.recv(8 - len(got))
                if not data:
                    return None
                got += data
            return time.monotonic() - start
        except socket.timeout:
            return float("inf")
        except OSError:
            return None


def first_new_tunnel(local, give_up_after):
    """Seconds until a newly opened tunnel echoed a payload, or None."""
    start = time.monotonic()
    while time.monotonic() - start < give_up_after:
        if s.roundtrip(local, b"x" * 1000, timeout=5):
            return time.monotonic() - start
        time.sleep(0.5)
    return None


def describe(result):
    if result is None:
        return "closed"
    if result == float("inf"):
        return "no answer"
    return f"answered in {result:.2f}s"


# --- cases ---

class Pair:
    def __init__(self, h, n):
        self.udp, self.local = UDP_BASE + n, LOCAL_BASE + n
        self.server = h.start([h.bin.server, f"--listen=127.0.0.1:{self.udp}",
                               f"--target=127.0.0.1:{s.ECHO_PORT}", s.KEY, IDLE],
                              f"clock-server{n}.log")
        self.client = h.start([h.bin.client, f"--local=127.0.0.1:{self.local}",
                               f"--remote=127.0.0.1:{self.udp}", s.KEY, IDLE],
                              f"clock-client{n}.log")
        time.sleep(2)
        s.check(s.roundtrip(self.local, b"warm up" * 100), f"pair {n} tunnels")
        self.tunnel = Tunnel(self.local)
        s.check(self.tunnel.ping(10) not in (None, float("inf")),
                f"pair {n} long-lived tunnel answers")

    def stop(self):
        s.Harness.stop(self.server, self.client)


def case_client_asleep(h):
    p = Pair(h, 0)
    freeze(p.client)
    time.sleep(25)  # past both 10s idle timeouts
    thaw(p.client)
    old = p.tunnel.ping(15)
    print(f"client asleep: tunnel opened before: {describe(old)}", flush=True)
    new = first_new_tunnel(p.local, 30)
    s.check(new is not None, "client asleep: a new tunnel works after waking" +
            (f" ({new:.1f}s)" if new is not None else ""))
    s.check_no_spin("client asleep", [p.server, p.client])
    p.stop()


def case_clock_step(h, n, seconds, label):
    p = Pair(h, n)
    set_clock_by(seconds)
    try:
        old = p.tunnel.ping(30)
        print(f"{label}: tunnel opened before: {describe(old)}", flush=True)
        new = first_new_tunnel(p.local, 30)
        print(f"{label}: new tunnel: " +
              (f"works after {new:.1f}s" if new is not None else
               "not working after 30s"), flush=True)
        s.check_no_spin(label, [p.server, p.client])
    finally:
        p.stop()
        set_clock_by(-seconds)


def main():
    binaries = s.Binaries(sys.argv[1] if len(sys.argv) > 1 else ".")
    h = s.Harness(binaries, tempfile.mkdtemp(prefix="quictun-clock-"))
    s.serve_forever(s.ECHO_PORT, s.echo)
    stop_time_sync()
    cases = [
        lambda: case_client_asleep(h),
        lambda: case_clock_step(h, 1, 2 * 3600, "clock +2h"),
        lambda: case_clock_step(h, 2, -2, "clock -2s"),
        lambda: case_clock_step(h, 3, -600, "clock -10min"),
    ]
    for case in cases:
        try:
            case()
        except Exception as e:  # one broken case must not hide the rest
            s.check(False, f"case raised {e!r}")
            for proc, _ in h.procs:
                h.stop(proc)
    h.report_logs()
    print("FAILURES:", s.failures if s.failures else "none")
    sys.exit(1 if s.failures else 0)


if __name__ == "__main__":
    main()
