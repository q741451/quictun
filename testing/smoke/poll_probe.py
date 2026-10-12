#!/usr/bin/env python3
"""What poll() (WSAPoll() on Windows) and select() report on this OS.

    poll_probe.py

Prints, for each case, which events the call returns and whether reading
clears them. It asserts nothing: QuicPollEventLoop is written against what
Linux reports, so the output is meant to be read side by side with Linux's,
and any difference checked against quic_poll_event_loop.cc. The cases are
the ones where a level-triggered loop can spin on a condition nothing
consumes:

  1   a TCP urgent (out-of-band) byte, and 1b the data around it
  2   the peer shuts down its sending side; we keep sending into a full buffer
  3   the peer resets; we only wait for writable
  4   a non-blocking connect() to a closed port
  5   a connected UDP socket whose peer port is closed (ICMP unreachable)

Run it on a new OS release (or under a new Windows build) before trusting
quictun's event loop there.
"""

import ctypes
import select
import socket
import struct
import sys
import time

WIN = sys.platform == "win32"
if WIN:
    ws2 = ctypes.WinDLL("ws2_32")
    class PFD(ctypes.Structure):
        _fields_ = [("fd", ctypes.c_size_t), ("events", ctypes.c_short), ("revents", ctypes.c_short)]
    ws2.WSAPoll.argtypes = [ctypes.POINTER(PFD), ctypes.c_ulong, ctypes.c_int]
    RDNORM, RDBAND, WRNORM, ERR, HUP, NVAL = 0x100, 0x200, 0x10, 0x1, 0x2, 0x4
    IN, OUT, PRI = RDNORM | RDBAND, WRNORM, 0x400
else:
    IN, OUT, PRI = select.POLLIN, select.POLLOUT, select.POLLPRI
    RDNORM, RDBAND, WRNORM = select.POLLRDNORM, select.POLLRDBAND, select.POLLWRNORM
    ERR, HUP, NVAL = select.POLLERR, select.POLLHUP, select.POLLNVAL
RDHUP = getattr(select, "POLLRDHUP", 0)
if WIN:
    NAMES = [(RDNORM, "RDNORM"), (RDBAND, "RDBAND"), (WRNORM, "WRNORM"),
             (ERR, "ERR"), (HUP, "HUP"), (NVAL, "NVAL")]
else:
    NAMES = [(IN, "IN"), (PRI, "PRI"), (OUT, "OUT"), (RDNORM, "RDNORM"),
             (RDBAND, "RDBAND"), (WRNORM, "WRNORM"), (ERR, "ERR"), (HUP, "HUP"),
             (NVAL, "NVAL"), (RDHUP, "RDHUP")]

def fmt(rev):
    out, seen = [], set()
    for b, n in NAMES:
        if b and (rev & b) == b and b not in seen:
            out.append(n); seen.add(b)
    return "|".join(out) or "-"

def poll(s, events, name=None):
    if WIN:
        p = PFD(s.fileno(), events, 0)
        r = ws2.WSAPoll(ctypes.byref(p), 1, 0)
        return f"poll({name or events:>8}) ret={r} {fmt(p.revents)}" + (f" err={ws2.WSAGetLastError()}" if r < 0 else "")
    p = select.poll(); p.register(s, events)
    res = p.poll(0)
    return f"poll({name or events:>8}) ret={len(res)} {fmt(res[0][1]) if res else '-'}"

def sel(s, r=False, w=False, x=False):
    try:
        rr, ww, xx = select.select([s] if r else [], [s] if w else [], [s] if x else [], 0)
    except OSError as e:
        return f"select({'r' if r else ''}{'w' if w else ''}{'x' if x else ''}) error {e}"
    got = ("r" if rr else "") + ("w" if ww else "") + ("x" if xx else "")
    return f"select({'r' if r else ''}{'w' if w else ''}{'x' if x else ''}) -> {got or '-'}"

def tcp_pair():
    ls = socket.create_server(("127.0.0.1", 0))
    a = socket.create_connection(ls.getsockname())
    b, _ = ls.accept()
    ls.close()
    b.setblocking(False)
    return a, b

def try_recv(s, n=65536):
    try:
        d = s.recv(n)
        return f"recv {len(d)} bytes {d[:8]!r}"
    except BlockingIOError:
        return "recv WOULDBLOCK"
    except OSError as e:
        return f"recv error {getattr(e, 'winerror', None) or e.errno}"

def fill(s):
    n = 0
    try:
        while True:
            n += s.send(b"z" * 65536)
    except BlockingIOError:
        pass
    return n

print(f"### {sys.platform}")

print("== 1. urgent (OOB) byte only")
a, b = tcp_pair()
a.send(b"U", socket.MSG_OOB); time.sleep(0.2)
for line in (poll(b, IN, "IN"), poll(b, RDNORM, "RDNORM"), sel(b, r=True), sel(b, x=True)):
    print("  ", line)
print("   ", try_recv(b))
print("   after recv:", poll(b, IN, "IN"), "|", poll(b, RDNORM, "RDNORM"), "|", sel(b, r=True), "|", sel(b, x=True))
a.close(); b.close()

print("== 1b. normal data around an urgent byte: AB, urgent U, CD")
a, b = tcp_pair()
a.send(b"AB"); time.sleep(0.05); a.send(b"U", socket.MSG_OOB); time.sleep(0.05); a.send(b"CD"); time.sleep(0.2)
for i in range(4):
    st = poll(b, RDNORM, "RDNORM")
    print(f"   {st} -> {try_recv(b)}")
a.close(); b.close()

print("== 2. peer shut down sending (FIN), we keep sending, peer never reads")
a, b = tcp_pair()
a.shutdown(socket.SHUT_WR); time.sleep(0.2)
print("  ", poll(b, IN, "IN"), "|", poll(b, OUT, "OUT"), "|", poll(b, 0, "0"))
print("  ", try_recv(b))
print("   sent", fill(b), "bytes until the send buffer is full")
time.sleep(0.2)
print("  ", poll(b, OUT, "OUT"), "|", poll(b, 0, "0"), "|", sel(b, w=True), "|", sel(b, w=True, x=True))
a.close(); b.close()

print("== 3. peer reset (RST), we only wait for writable")
a, b = tcp_pair()
fill(b)
a.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("HH" if WIN else "ii", 1, 0))  # abortive close: RST
a.close(); time.sleep(0.2)
print("  ", poll(b, OUT, "OUT"), "|", poll(b, 0, "0"), "|", sel(b, w=True), "|", sel(b, w=True, x=True), "|", sel(b, r=True))
print("  ", try_recv(b))
b.close()

print("== 4. non-blocking connect to a closed port")
dead = socket.socket(); dead.bind(("127.0.0.1", 0)); port = dead.getsockname()[1]; dead.close()
for api in ("poll", "select"):
    c = socket.socket(); c.setblocking(False)
    try:
        c.connect(("127.0.0.1", port))
    except (BlockingIOError, OSError):
        pass
    time.sleep(3)  # Windows retries a refused SYN for about 2s
    print("  ", poll(c, OUT, "OUT") if api == "poll" else sel(c, w=True, x=True),
          "SO_ERROR", c.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR))
    c.close()

print("== 5. connected UDP, peer port closed (ICMP unreachable)")
dead = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); dead.bind(("127.0.0.1", 0))
port = dead.getsockname()[1]; dead.close()
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("127.0.0.1", 0))
u.connect(("127.0.0.1", port)); u.setblocking(False)
u.send(b"ping"); time.sleep(0.2)
print("  ", poll(u, IN, "IN"), "|", poll(u, 0, "0"), "|", sel(u, r=True))
print("   SO_ERROR", u.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR))
print("  ", poll(u, IN, "IN"), "|", try_recv(u), "|", poll(u, IN, "IN"))
u.close()
