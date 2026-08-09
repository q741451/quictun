"""Reusable chaotic-traffic-generator threads against a quictun_client's
--local TCP listen address. Used by both the server-side and client-side
chaos test drivers.
"""
import random
import socket
import threading
import time


def short_echo(local_addr, timeout=6):
    payload = bytes(random.randint(65, 90) for _ in range(random.randint(16, 512)))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect(local_addr)
        s.sendall(payload)
        got = b""
        while len(got) < len(payload):
            chunk = s.recv(65536)
            if not chunk:
                break
            got += chunk
        return got == payload
    finally:
        try:
            s.close()
        except Exception:
            pass


def big_download(local_addr, n, timeout=20):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect(local_addr)
        s.sendall(f"BIGDATA:{n}\n".encode())
        total = 0
        while total < n:
            chunk = s.recv(262144)
            if not chunk:
                break
            total += len(chunk)
        return total == n
    finally:
        try:
            s.close()
        except Exception:
            pass


def big_download_early_halfclose(local_addr, n, timeout=20):
    """Requests a big download, then immediately shuts down the write side
    (signalling "no more data from me" quickly) while still reading the
    full response -- reproduces the "peer's fin arrives while WE still have
    a lot of our own not-yet-flushed data queued the other direction"
    scenario that MaybeCloseAfterQuicFin() needs to handle without
    truncating."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect(local_addr)
        s.sendall(f"BIGDATA:{n}\n".encode())
        s.shutdown(socket.SHUT_WR)
        total = 0
        while total < n:
            chunk = s.recv(262144)
            if not chunk:
                break
            total += len(chunk)
        return total == n
    finally:
        try:
            s.close()
        except Exception:
            pass


def idle_then_close(local_addr, idle_s, timeout=6):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect(local_addr)
        time.sleep(idle_s)
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def abrupt_close(local_addr, timeout=6):
    """Connect, send a partial/garbage chunk, then hard-RST via SO_LINGER=0
    instead of a clean close -- simulates a client that vanishes mid-flight."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect(local_addr)
        s.sendall(b"partial-garbage-no-newline-" * random.randint(1, 5))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                     b"\x01\x00\x00\x00\x00\x00\x00\x00")
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def actor_loop(local_addr, stop_event, stats, stats_lock, big_data_kb=256):
    """One thread's worth of chaotic activity until stop_event is set."""
    ops = ["short_echo"] * 6 + ["big_download"] * 2 + ["idle_then_close"] * 1 + ["abrupt_close"] * 1
    while not stop_event.is_set():
        op = random.choice(ops)
        exc_name = None
        try:
            if op == "short_echo":
                ok = short_echo(local_addr)
            elif op == "big_download":
                ok = big_download(local_addr, big_data_kb * 1024)
            elif op == "idle_then_close":
                ok = idle_then_close(local_addr, random.uniform(0.5, 2.0))
            else:
                ok = abrupt_close(local_addr)
        except Exception as e:
            ok = False
            exc_name = type(e).__name__
        with stats_lock:
            if ok:
                key = op + "_ok"
            elif exc_name:
                key = f"{op}_fail_{exc_name}"
            else:
                key = op + "_fail_returned_false"
            stats[key] = stats.get(key, 0) + 1


def run_actors(local_addr, duration_s, n_threads, big_data_kb=256):
    """Runs n_threads actor loops against local_addr for duration_s seconds.
    Returns the aggregated stats dict."""
    stop_event = threading.Event()
    stats = {}
    stats_lock = threading.Lock()
    threads = [
        threading.Thread(target=actor_loop,
                          args=(local_addr, stop_event, stats, stats_lock, big_data_kb),
                          daemon=True)
        for _ in range(n_threads)
    ]
    for t in threads:
        t.start()
    time.sleep(duration_s)
    stop_event.set()
    for t in threads:
        t.join(timeout=10)
    return stats
