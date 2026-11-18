"""Generate live LAB1A traffic for Wireshark demos.

Start the script, capture loopback traffic with the sniffer (or Wireshark),
and the script's TCP client/server will exchange valid request, response and
heartbeat messages on 127.0.0.1:9999.

    python tools/lab1a_demo.py --rounds 5

The protocol matches wireshark/lab1a.lua:

    magic "L1A1" | version u8 | type u8 | seq u16 | length u16 | payload
"""

from __future__ import annotations

import argparse
import socket
import struct
import threading
import time

HEADER = struct.Struct("!4sBBHH")
MAGIC = b"L1A1"
TYPE_REQUEST = 1
TYPE_RESPONSE = 2
TYPE_HEARTBEAT = 3


def pack_message(msg_type: int, seq: int, payload: bytes = b"") -> bytes:
    return HEADER.pack(MAGIC, 1, msg_type, seq & 0xFFFF, len(payload)) + payload


def recv_exact(sock: socket.socket, size: int) -> bytes | None:
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_message(sock: socket.socket) -> tuple[int, int, bytes] | None:
    header = recv_exact(sock, HEADER.size)
    if header is None:
        return None
    magic, version, msg_type, seq, length = HEADER.unpack(header)
    if magic != MAGIC or version != 1:
        raise ValueError(f"bad LAB1A header: {header!r}")
    payload = recv_exact(sock, length)
    if payload is None:
        return None
    return msg_type, seq, payload


class Lab1aServer(threading.Thread):
    def __init__(self, host: str, port: int) -> None:
        super().__init__(name="lab1a-server", daemon=True)
        self.host = host
        self.port = port
        self.ready = threading.Event()
        self.error: BaseException | None = None
        self.received: list[tuple[int, int, bytes]] = []

    def run(self) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((self.host, self.port))
                listener.listen(1)
                listener.settimeout(10.0)
                self.ready.set()
                connection, _address = listener.accept()
                with connection:
                    connection.settimeout(10.0)
                    while True:
                        message = recv_message(connection)
                        if message is None:
                            break
                        msg_type, seq, payload = message
                        self.received.append(message)
                        if msg_type == TYPE_REQUEST:
                            reply = pack_message(
                                TYPE_RESPONSE,
                                seq,
                                b"OK " + payload[:40],
                            )
                        elif msg_type == TYPE_HEARTBEAT:
                            reply = pack_message(TYPE_HEARTBEAT, seq)
                        else:
                            reply = pack_message(TYPE_RESPONSE, seq, b"unsupported")
                        connection.sendall(reply)
                        print(
                            f"[server] 收到 type={msg_type} seq={seq} "
                            f"len={len(payload)}，已回复 {len(reply)} 字节"
                        )
        except BaseException as exc:  # keep the thread's failure visible
            self.error = exc
            self.ready.set()


def run_client(host: str, port: int, rounds: int, delay: float) -> int:
    client_sent = 0
    with socket.create_connection((host, port), timeout=5.0) as sock:
        sock.settimeout(5.0)
        for index in range(rounds):
            seq = index + 1
            payload = f"GET /lab1a/{seq}".encode("ascii")
            request = pack_message(TYPE_REQUEST, seq, payload)
            sock.sendall(request)
            client_sent += len(request)
            print(f"[client] 请求 seq={seq} len={len(payload)}")

            reply = recv_message(sock)
            if reply is None:
                raise RuntimeError("server closed before replying to request")
            reply_type, reply_seq, reply_payload = reply
            if reply_type != TYPE_RESPONSE or reply_seq != seq:
                raise RuntimeError(
                    f"unexpected reply: type={reply_type} seq={reply_seq}"
                )
            print(
                f"[client] 应答 seq={reply_seq} "
                f"payload={reply_payload.decode('ascii', 'replace')!r}"
            )

            heartbeat_seq = 1000 + seq
            heartbeat = pack_message(TYPE_HEARTBEAT, heartbeat_seq)
            sock.sendall(heartbeat)
            client_sent += len(heartbeat)
            print(f"[client] 心跳 seq={heartbeat_seq}")

            heartbeat_reply = recv_message(sock)
            if heartbeat_reply is None:
                raise RuntimeError("server closed before replying to heartbeat")
            hb_type, hb_seq, _hb_payload = heartbeat_reply
            if hb_type != TYPE_HEARTBEAT or hb_seq != heartbeat_seq:
                raise RuntimeError(
                    f"unexpected heartbeat reply: type={hb_type} seq={hb_seq}"
                )
            print(f"[client] 心跳应答 seq={hb_seq}")

            if delay > 0 and index + 1 < rounds:
                time.sleep(delay)
    return client_sent


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument(
        "--delay",
        type=float,
        default=0.15,
        help="seconds between rounds (default: 0.15)",
    )
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error("--rounds must be at least 1")

    server = Lab1aServer(args.host, args.port)
    server.start()
    if not server.ready.wait(5.0):
        print("[error] server did not become ready")
        return 1
    if server.error is not None:
        print(f"[error] server: {server.error}")
        return 1

    try:
        client_sent = run_client(args.host, args.port, args.rounds, args.delay)
    except Exception as exc:
        print(f"[error] client: {exc}")
        return 1
    finally:
        server.join(timeout=5.0)

    if server.error is not None:
        print(f"[error] server: {server.error}")
        return 1
    print(
        f"完成: 客户端发送 {client_sent} 字节，服务端收到 "
        f"{len(server.received)} 条 LAB1A 消息"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
