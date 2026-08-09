#!/usr/bin/env python3
"""Application-level network impairment relay for chaos-testing quictun.

Kernel `tc netem` in this environment applies loss correctly but NOT delay
(confirmed empirically: a 500ms netem delay left real UDP RTT sub-millisecond
and `time ping -c1` returned in 1ms). This relay reproduces both loss and
delay at the application layer instead, independently per hop, so each of
quictun's three network legs (QUIC/UDP between client and server, TCP between
test clients and quictun_client's --local, TCP between quictun_server and
--target) can be impaired on its own.

Modes:
  udp  - NAT-style UDP relay: listens on --listen, forwards each datagram to
         --upstream, and relays replies back to the originating client
         address, tracking per-client-flow state. Independently drops
         (--loss) and delays (--delay-ms, +/- --jitter-ms) each direction.
  tcp  - Forwarding TCP relay: for each accepted connection, dials
         --upstream and pumps bytes in both directions, delaying each
         forwarded chunk and, with probability --reset-prob, abruptly
         closing (RST-like) a connection at a random point during its
         lifetime to simulate the kind of severe failure a bad TCP network
         path actually produces (as opposed to invisible, transparently-
         recovered single-segment loss).
"""
import argparse
import asyncio
import random
import socket
import sys
import time

# Keeps blackholed TCP connections' StreamWriters alive (see
# handle_tcp_conn's --blackhole-prob handling) -- without a strong
# reference, Python's GC would eventually collect and implicitly close
# them, sending a real FIN and defeating the "silently vanish forever"
# simulation.
BLACKHOLED_CONNS = []


def parse_addr(s):
    host, port = s.rsplit(":", 1)
    return host, int(port)


async def maybe_delay(delay_ms, jitter_ms):
    if delay_ms <= 0 and jitter_ms <= 0:
        return
    d = delay_ms + random.uniform(-jitter_ms, jitter_ms)
    if d > 0:
        await asyncio.sleep(d / 1000.0)


class UdpRelayProtocol(asyncio.DatagramProtocol):
    """One instance per upstream flow (i.e. per distinct client address)."""

    def __init__(self, client_addr, listen_transport, loss, delay_ms, jitter_ms, stats):
        self.client_addr = client_addr
        self.listen_transport = listen_transport
        self.loss = loss
        self.delay_ms = delay_ms
        self.jitter_ms = jitter_ms
        self.stats = stats
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        # upstream -> client direction
        if random.random() < self.loss:
            self.stats["s2c_dropped"] += 1
            return
        self.stats["s2c_forwarded"] += 1
        asyncio.ensure_future(self._forward_to_client(data))

    async def _forward_to_client(self, data):
        await maybe_delay(self.delay_ms, self.jitter_ms)
        if self.listen_transport is not None:
            self.listen_transport.sendto(data, self.client_addr)


class UdpListener(asyncio.DatagramProtocol):
    def __init__(self, upstream_addr, loss, delay_ms, jitter_ms, idle_gc_s, stats):
        self.upstream_addr = upstream_addr
        self.loss = loss
        self.delay_ms = delay_ms
        self.jitter_ms = jitter_ms
        self.idle_gc_s = idle_gc_s
        self.stats = stats
        self.transport = None
        self.flows = {}  # client_addr -> (transport, protocol, last_seen)
        # addr -> list of pending datagrams, reserved as soon as flow setup
        # starts (synchronously, before the first `await`) so a retransmit
        # arriving while setup is still in flight queues onto the SAME
        # upstream flow instead of racing a second create_datagram_endpoint()
        # for the same client address -- that race (fixed here) previously
        # gave the server two independent upstream sockets, at two different
        # source ports, both relaying copies of what was really one client's
        # retransmitted Initial packet; the server's own address-keyed
        # connection map (see quictun_server_driver.cc's ProcessPacket())
        # then had no way to tell they were the same connection, so it
        # created a second, independent QuicConnection with the same
        # connection ID but unrelated key material -- a test-relay bug, not
        # a quictun one, that looked exactly like a broken 0-RTT-rejection
        # fallback until traced back here.
        self.pending = {}

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if random.random() < self.loss:
            self.stats["c2s_dropped"] += 1
            return
        self.stats["c2s_forwarded"] += 1
        flow = self.flows.get(addr)
        if flow is not None:
            transport, protocol, _ = flow
            self.flows[addr] = (transport, protocol, time.time())
            asyncio.ensure_future(self._forward_to_upstream(transport, data))
            return
        if addr in self.pending:
            # Setup already in flight for this address -- queue onto it
            # rather than starting a second, duplicate upstream flow.
            self.pending[addr].append(data)
            return
        self.pending[addr] = []
        loop = asyncio.get_event_loop()
        coro = loop.create_datagram_endpoint(
            lambda: UdpRelayProtocol(addr, self.transport, self.loss,
                                      self.delay_ms, self.jitter_ms, self.stats),
            remote_addr=self.upstream_addr)
        asyncio.ensure_future(self._setup_flow(addr, coro, data))

    async def _setup_flow(self, addr, coro, first_data):
        transport, protocol = await coro
        self.flows[addr] = (transport, protocol, time.time())
        queued = self.pending.pop(addr, [])
        await self._forward_to_upstream(transport, first_data)
        for data in queued:
            await self._forward_to_upstream(transport, data)

    async def _forward_to_upstream(self, transport, data):
        await maybe_delay(self.delay_ms, self.jitter_ms)
        transport.sendto(data)

    async def gc_loop(self):
        while True:
            await asyncio.sleep(5)
            now = time.time()
            stale = [a for a, (_, _, last) in self.flows.items()
                     if now - last > self.idle_gc_s]
            for a in stale:
                t, _, _ = self.flows.pop(a)
                t.close()


async def run_udp(args):
    loop = asyncio.get_event_loop()
    listener = UdpListener(args.upstream, args.loss, args.delay_ms,
                            args.jitter_ms, args.idle_gc_s,
                            {"c2s_forwarded": 0, "c2s_dropped": 0,
                             "s2c_forwarded": 0, "s2c_dropped": 0})
    transport, _ = await loop.create_datagram_endpoint(
        lambda: listener, local_addr=args.listen)
    asyncio.ensure_future(listener.gc_loop())
    print(f"[udp-relay] {args.listen} -> {args.upstream} "
          f"loss={args.loss} delay={args.delay_ms}ms jitter={args.jitter_ms}ms",
          flush=True)
    try:
        while True:
            await asyncio.sleep(10)
            s = listener.stats
            print(f"[udp-relay stats] c2s: fwd={s['c2s_forwarded']} "
                  f"drop={s['c2s_dropped']} | s2c: fwd={s['s2c_forwarded']} "
                  f"drop={s['s2c_dropped']} | flows={len(listener.flows)}",
                  flush=True)
    finally:
        transport.close()


async def tcp_pump(reader, writer, delay_ms, jitter_ms, label, stats):
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            await maybe_delay(delay_ms, jitter_ms)
            writer.write(chunk)
            await writer.drain()
            stats[label] = stats.get(label, 0) + len(chunk)
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle_tcp_conn(client_reader, client_writer, args, stats):
    stats["conns"] = stats.get("conns", 0) + 1
    peer = client_writer.get_extra_info("peername")
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection(
            *args.upstream)
    except OSError as e:
        stats["upstream_connect_fail"] = stats.get("upstream_connect_fail", 0) + 1
        client_writer.close()
        return

    # Probabilistically go silent instead of forwarding anything at all --
    # never FIN, never RST, just accept the TCP handshake and then let
    # everything vanish, simulating a network partition or a broken
    # middlebox eating packets. Unlike --reset-prob (a clean, immediate,
    # detectable failure), this is deliberately the hardest case: nothing
    # ever tells either endpoint the connection is dead, so the only way to
    # recover is a timeout on one end deciding to give up.
    if args.blackhole_prob > 0 and random.random() < args.blackhole_prob:
        stats["blackholed"] = stats.get("blackholed", 0) + 1
        BLACKHOLED_CONNS.append((client_writer, upstream_writer))  # keep alive

        async def drain_forever(reader):
            try:
                while True:
                    chunk = await reader.read(1 << 16)
                    if not chunk:
                        return  # peer actually closed -- stop draining that side
            except Exception:
                return

        # Keep consuming (and discarding) anything either side sends, for
        # as long as the process runs -- never close, never FIN, never RST.
        asyncio.ensure_future(drain_forever(client_reader))
        asyncio.ensure_future(drain_forever(upstream_reader))
        return

    # Probabilistically inject a mid-transfer forced reset, simulating a
    # severely-bad TCP path (not transparently-recoverable single-segment
    # loss, which a userspace relay can't meaningfully reproduce).
    reset_task = None
    if args.reset_prob > 0 and random.random() < args.reset_prob:
        delay_s = random.uniform(0.01, args.reset_after_s)

        async def do_reset():
            await asyncio.sleep(delay_s)
            stats["forced_resets"] = stats.get("forced_resets", 0) + 1
            for w in (client_writer, upstream_writer):
                try:
                    sock = w.get_extra_info("socket")
                    if sock is not None:
                        # SO_LINGER with 0 timeout forces a real RST instead
                        # of a graceful FIN, matching what a real flaky
                        # network path produces.
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                         b"\x01\x00\x00\x00\x00\x00\x00\x00")
                except Exception:
                    pass
                try:
                    w.close()
                except Exception:
                    pass

        reset_task = asyncio.ensure_future(do_reset())

    c2u = asyncio.ensure_future(tcp_pump(client_reader, upstream_writer,
                                          args.delay_ms, args.jitter_ms,
                                          "c2u_bytes", stats))
    u2c = asyncio.ensure_future(tcp_pump(upstream_reader, client_writer,
                                          args.delay_ms, args.jitter_ms,
                                          "u2c_bytes", stats))
    await asyncio.gather(c2u, u2c, return_exceptions=True)
    if reset_task:
        reset_task.cancel()


async def run_tcp(args):
    stats = {}

    async def on_conn(r, w):
        await handle_tcp_conn(r, w, args, stats)

    server = await asyncio.start_server(on_conn, *args.listen)
    print(f"[tcp-relay] {args.listen} -> {args.upstream} "
          f"delay={args.delay_ms}ms jitter={args.jitter_ms}ms "
          f"reset_prob={args.reset_prob} reset_after<={args.reset_after_s}s",
          flush=True)
    async with server:
        while True:
            await asyncio.sleep(10)
            print(f"[tcp-relay stats] {stats}", flush=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["udp", "tcp"], required=True)
    p.add_argument("--listen", type=parse_addr, required=True)
    p.add_argument("--upstream", type=parse_addr, required=True)
    p.add_argument("--loss", type=float, default=0.0, help="0.0-1.0, udp only")
    p.add_argument("--delay-ms", type=float, default=0.0)
    p.add_argument("--jitter-ms", type=float, default=0.0)
    p.add_argument("--idle-gc-s", type=float, default=120.0, help="udp flow GC")
    p.add_argument("--reset-prob", type=float, default=0.0,
                   help="tcp only: probability a connection gets force-reset")
    p.add_argument("--reset-after-s", type=float, default=2.0,
                   help="tcp only: max random delay before a forced reset")
    p.add_argument("--blackhole-prob", type=float, default=0.0,
                   help="tcp only: probability a connection goes silently "
                        "dark forever (no FIN, no RST -- see the comment "
                        "on handle_tcp_conn)")
    args = p.parse_args()

    if args.mode == "udp":
        asyncio.run(run_udp(args))
    else:
        asyncio.run(run_tcp(args))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
