#!/usr/bin/env python3
"""Backend TCP service quictun_server's --target points to.

Protocol: reads one line. If it's "BIGDATA:<n>\n", sends n bytes back then
closes. Otherwise treats the connection as a plain echo (loops forever
echoing whatever it receives, for as long as the peer keeps it open).
"""
import socket
import sys
import threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 19200


MAGIC = b"BIGDATA:"


def handle(conn):
    try:
        conn.settimeout(30)
        # Peek just enough to tell BIGDATA:<n>\n apart from plain echo
        # traffic, WITHOUT requiring a newline for ordinary echo data (most
        # chaos-test payloads are fixed-size binary blobs with no framing at
        # all -- waiting on a '\n' that will never arrive would just hang).
        buf = b""
        while len(buf) < len(MAGIC):
            chunk = conn.recv(len(MAGIC) - len(buf))
            if not chunk:
                return
            buf += chunk
        if buf == MAGIC:
            # BIGDATA mode: read the rest of the line for the byte count.
            while b"\n" not in buf:
                chunk = conn.recv(64)
                if not chunk:
                    return
                buf += chunk
            line, rest = buf.split(b"\n", 1)
            n = int(line[len(MAGIC):])
            sent = 0
            payload = b"D" * 65536
            while sent < n:
                chunk = payload[: min(len(payload), n - sent)]
                conn.sendall(chunk)
                sent += len(chunk)
            return
        # Plain echo mode: echo back whatever was already peeked, then keep
        # echoing anything further for as long as the peer keeps sending.
        conn.sendall(buf)
        while True:
            data = conn.recv(65536)
            if not data:
                break
            conn.sendall(data)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PORT))
    s.listen(1024)
    print(f"chaos_target listening on 127.0.0.1:{PORT}", flush=True)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
