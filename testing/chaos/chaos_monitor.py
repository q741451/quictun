"""Lightweight /proc-based process monitor: FD count, RSS memory, CPU%."""
import os
import time


def read_rss_kb(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except Exception:
        return None
    return None


def read_fd_count(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except Exception:
        return None


def read_cpu_ticks(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().split()
        # utime=14th field, stime=15th (1-indexed)
        return int(parts[13]) + int(parts[14])
    except Exception:
        return None


class Sampler:
    """Call sample() periodically; computes instantaneous %CPU between calls."""

    def __init__(self, pid):
        self.pid = pid
        self._hz = os.sysconf("SC_CLK_TCK")
        self._last_ticks = None
        self._last_time = None
        self.history = []  # list of dicts: t, fds, rss_kb, cpu_pct

    def sample(self):
        now = time.time()
        fds = read_fd_count(self.pid)
        rss = read_rss_kb(self.pid)
        ticks = read_cpu_ticks(self.pid)
        cpu_pct = None
        if ticks is not None and self._last_ticks is not None:
            dt = now - self._last_time
            if dt > 0:
                cpu_pct = 100.0 * ((ticks - self._last_ticks) / self._hz) / dt
        if ticks is not None:
            self._last_ticks = ticks
            self._last_time = now
        entry = {"t": now, "fds": fds, "rss_kb": rss, "cpu_pct": cpu_pct}
        self.history.append(entry)
        return entry

    def alive(self):
        return read_fd_count(self.pid) is not None

    def summary(self):
        fds = [h["fds"] for h in self.history if h["fds"] is not None]
        rss = [h["rss_kb"] for h in self.history if h["rss_kb"] is not None]
        cpu = [h["cpu_pct"] for h in self.history if h["cpu_pct"] is not None]
        return {
            "fds_min": min(fds) if fds else None,
            "fds_max": max(fds) if fds else None,
            "fds_last": fds[-1] if fds else None,
            "fds_first": fds[0] if fds else None,
            "rss_kb_first": rss[0] if rss else None,
            "rss_kb_last": rss[-1] if rss else None,
            "rss_kb_max": max(rss) if rss else None,
            "cpu_pct_max": max(cpu) if cpu else None,
            "cpu_pct_last": cpu[-1] if cpu else None,
        }
