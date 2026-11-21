#!/usr/bin/env python3
"""MC Server Manager relay - runs on your own Linux server (VPS).

Friends connect to this machine; traffic is tunnelled to your home PC over a
connection your PC opens itself, so your home IP is never revealed and no
router setup is needed.  Java (TCP) and Bedrock (UDP) are both supported.
"""
import asyncio, hmac, os, struct, sys, time

TOKEN = (os.environ.get("MCRELAY_TOKEN") or (sys.argv[1] if len(sys.argv) > 1 else "")).encode()
CTRL_PORT = int(os.environ.get("MCRELAY_PORT", "47800"))
BIND = os.environ.get("MCRELAY_BIND", "0.0.0.0")
if len(TOKEN) < 16:
    sys.exit("MCRELAY_TOKEN missing or too short")

T_LISTEN, T_OK, T_ERR, T_NEWCONN, T_UDP, T_PING = 1, 2, 3, 4, 5, 6
HDR = struct.Struct(">BII")

home = None            # current Home
listeners = {}         # (proto, port) -> server / transport
pending = {}           # conn id -> Future[(reader, writer)]
udp_by_key = {}        # key -> [transport, addr, last_seen]
udp_by_addr = {}       # (port, addr) -> key
next_id = 1


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def new_id():
    global next_id
    next_id = (next_id + 1) % 0x7FFFFFFF or 1
    return next_id


class Home:
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer

    def send(self, t, i, payload=b""):
        if self.writer.is_closing():
            return
        self.writer.write(HDR.pack(t, i, len(payload)) + payload)


async def pipe(r, w):
    try:
        while True:
            data = await r.read(65536)
            if not data:
                break
            w.write(data)
            await w.drain()
    except Exception:
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


async def on_player_tcp(reader, writer, port):
    if home is None:
        writer.close()
        return
    cid = new_id()
    fut = asyncio.get_running_loop().create_future()
    pending[cid] = fut
    home.send(T_NEWCONN, cid, struct.pack(">H", port))
    try:
        hr, hw = await asyncio.wait_for(fut, 15)
    except Exception:
        writer.close()
        return
    finally:
        pending.pop(cid, None)
    await asyncio.gather(pipe(reader, hw), pipe(hr, writer))


class UdpListener(asyncio.DatagramProtocol):
    def __init__(self, port):
        self.port = port

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if home is None:
            return
        k = (self.port, addr)
        key = udp_by_addr.get(k)
        if key is None:
            key = new_id()
            udp_by_addr[k] = key
            udp_by_key[key] = [self.transport, addr, time.time(), k]
        udp_by_key[key][2] = time.time()
        home.send(T_UDP, key, struct.pack(">H", self.port) + data)


async def open_listener(proto, port):
    if (proto, port) in listeners:
        return
    loop = asyncio.get_running_loop()
    if proto == "tcp":
        srv = await asyncio.start_server(lambda r, w: on_player_tcp(r, w, port), BIND, port)
        listeners[(proto, port)] = srv
    else:
        tr, _ = await loop.create_datagram_endpoint(lambda: UdpListener(port), local_addr=(BIND, port))
        listeners[(proto, port)] = tr
    log("listening", proto, port)


def close_listeners():
    for (proto, port), l in list(listeners.items()):
        try:
            l.close()
        except Exception:
            pass
    listeners.clear()
    udp_by_key.clear()
    udp_by_addr.clear()


async def run_home(h):
    global home
    if home is not None:
        try:
            home.writer.close()
        except Exception:
            pass
        close_listeners()
    home = h
    log("home PC connected")
    try:
        while True:
            hdr = await asyncio.wait_for(h.reader.readexactly(HDR.size), 90)
            t, i, n = HDR.unpack(hdr)
            if n > 1 << 20:
                break
            payload = await h.reader.readexactly(n) if n else b""
            if t == T_LISTEN:
                proto, _, p = payload.decode().partition(":")
                try:
                    await open_listener(proto, int(p))
                    h.send(T_OK, i, payload)
                except Exception as e:
                    h.send(T_ERR, i, (payload.decode() + " " + str(e)).encode())
            elif t == T_UDP:
                c = udp_by_key.get(i)
                if c and len(payload) >= 2:
                    c[2] = time.time()
                    c[0].sendto(payload[2:], c[1])
            elif t == T_PING:
                h.send(T_PING, 0)
            await h.writer.drain()
    except Exception:
        pass
    finally:
        if home is h:
            home = None
            close_listeners()
            log("home PC disconnected")
        try:
            h.writer.close()
        except Exception:
            pass


async def on_control(reader, writer):
    try:
        line = (await asyncio.wait_for(reader.readline(), 10)).strip().split(b" ")
    except Exception:
        writer.close()
        return
    if len(line) >= 2 and hmac.compare_digest(line[1], TOKEN):
        if line[0] == b"AUTH":
            writer.write(b"OK\n")
            await writer.drain()
            await run_home(Home(reader, writer))
            return
        if line[0] == b"DATA" and len(line) == 3:
            fut = pending.get(int(line[2]))
            if fut and not fut.done():
                fut.set_result((reader, writer))
                return
    await asyncio.sleep(1)  # slow down guessing
    writer.close()


async def cleanup():
    while True:
        await asyncio.sleep(30)
        now = time.time()
        for key, c in list(udp_by_key.items()):
            if now - c[2] > 120:
                udp_by_key.pop(key, None)
                udp_by_addr.pop(c[3], None)


async def main():
    srv = await asyncio.start_server(on_control, "0.0.0.0", CTRL_PORT)
    log("MC relay ready on port", CTRL_PORT)
    asyncio.get_running_loop().create_task(cleanup())
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
