"""Build a small deterministic pcap that exercises the LAB1A dissector.

The generated capture is only a test/demo asset; it is ignored by Git because
the repository keeps code, not capture files.  Run it with:

    python tools/make_lab1a_pcap.py --out _setup/lab1a_demo.pcap

The frames contain a complete TCP handshake, a request/response/heartbeat
exchange, a second TCP stream, UDP traffic and four intentionally malformed
LAB1A messages.
"""

from __future__ import annotations

import argparse
import ipaddress
import struct
import time
from pathlib import Path

ETHERTYPE_IPV4 = 0x0800
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")


def checksum(data: bytes) -> int:
    """Internet checksum (RFC 1071) for an even-length byte string."""

    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_packet(
    src: str,
    dst: str,
    protocol: int,
    payload: bytes,
    identification: int,
    ttl: int = 64,
) -> bytes:
    src_bytes = ipaddress.IPv4Address(src).packed
    dst_bytes = ipaddress.IPv4Address(dst).packed
    total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        identification & 0xFFFF,
        0x4000,
        ttl,
        protocol,
        0,
        src_bytes,
        dst_bytes,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def tcp_segment(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
    window: int = 65535,
) -> bytes:
    offset_flags = (5 << 12) | flags
    header = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        offset_flags,
        window,
        0,
        0,
    )
    pseudo = (
        ipaddress.IPv4Address(src_ip).packed
        + ipaddress.IPv4Address(dst_ip).packed
        + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    )
    tcp_checksum = checksum(pseudo + header + payload)
    header = header[:16] + struct.pack("!H", tcp_checksum) + header[18:]
    return header + payload


def udp_datagram(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", src_port, dst_port, length, 0)
    return header + payload


def ethernet_frame(src_mac: bytes, dst_mac: bytes, payload: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", ETHERTYPE_IPV4) + payload


def lab1a_message(msg_type: int, seq: int, payload: bytes, version: int = 1) -> bytes:
    return (
        b"L1A1"
        + bytes((version & 0xFF, msg_type & 0xFF))
        + struct.pack("!HH", seq & 0xFFFF, len(payload) & 0xFFFF)
        + payload
    )


class CaptureBuilder:
    def __init__(self, start_ts: float | None = None) -> None:
        self.frames: list[tuple[float, bytes]] = []
        self.next_ts = time.time() if start_ts is None else start_ts
        self.ip_id = 1

    def add_ip(
        self,
        src: str,
        dst: str,
        protocol: int,
        payload: bytes,
        *,
        outbound: bool,
    ) -> None:
        ip = ipv4_packet(src, dst, protocol, payload, self.ip_id)
        self.ip_id += 1
        src_mac, dst_mac = (
            (CLIENT_MAC, SERVER_MAC) if outbound else (SERVER_MAC, CLIENT_MAC)
        )
        self.frames.append((self.next_ts, ethernet_frame(src_mac, dst_mac, ip)))
        self.next_ts += 0.05

    def add_tcp(
        self,
        src: str,
        dst: str,
        sport: int,
        dport: int,
        seq: int,
        ack: int,
        flags: int,
        payload: bytes = b"",
        *,
        outbound: bool | None = None,
    ) -> None:
        if outbound is None:
            outbound = sport != 9999
        segment = tcp_segment(src, dst, sport, dport, seq, ack, flags, payload)
        self.add_ip(src, dst, 6, segment, outbound=outbound)

    def add_udp(
        self,
        src: str,
        dst: str,
        sport: int,
        dport: int,
        payload: bytes,
        *,
        outbound: bool | None = None,
    ) -> None:
        if outbound is None:
            outbound = sport != 9999
        datagram = udp_datagram(src, dst, sport, dport, payload)
        self.add_ip(src, dst, 17, datagram, outbound=outbound)


def add_tcp_conversation(
    builder: CaptureBuilder,
    client_port: int,
    request_seq: int,
    request_payload: bytes,
    response_payload: bytes,
    heartbeat: bool = True,
) -> None:
    client = "127.0.0.1"
    server = "127.0.0.1"
    server_port = 9999
    client_isn = 1000 + client_port
    server_isn = 9000 + client_port
    client_next = client_isn + 1
    server_next = server_isn + 1

    builder.add_tcp(
        client, server, client_port, server_port, client_isn, 0, TCP_SYN
    )
    builder.add_tcp(
        server,
        client,
        server_port,
        client_port,
        server_isn,
        client_next,
        TCP_SYN | TCP_ACK,
    )
    builder.add_tcp(
        client, server, client_port, server_port, client_next, server_next, TCP_ACK
    )
    builder.add_tcp(
        client,
        server,
        client_port,
        server_port,
        client_next,
        server_next,
        TCP_PSH | TCP_ACK,
        request_payload,
    )
    client_next += len(request_payload)

    builder.add_tcp(
        server,
        client,
        server_port,
        client_port,
        server_next,
        client_next,
        TCP_PSH | TCP_ACK,
        response_payload,
    )
    server_next += len(response_payload)

    if heartbeat:
        heartbeat_payload = lab1a_message(3, request_seq + 1, b"")
        builder.add_tcp(
            client,
            server,
            client_port,
            server_port,
            client_next,
            server_next,
            TCP_PSH | TCP_ACK,
            heartbeat_payload,
        )
        client_next += len(heartbeat_payload)
        builder.add_tcp(
            server,
            client,
            server_port,
            client_port,
            server_next,
            client_next,
            TCP_ACK,
        )

    builder.add_tcp(
        client,
        server,
        client_port,
        server_port,
        client_next,
        server_next,
        TCP_FIN | TCP_ACK,
    )
    client_next += 1
    builder.add_tcp(
        server,
        client,
        server_port,
        client_port,
        server_next,
        client_next,
        TCP_FIN | TCP_ACK,
    )
    server_next += 1
    builder.add_tcp(
        client, server, client_port, server_port, client_next, server_next, TCP_ACK
    )


def build_demo_capture(path: str | Path) -> Path:
    builder = CaptureBuilder()
    client = "127.0.0.1"
    server = "127.0.0.1"

    # Stream 0: normal request / response / heartbeat.
    add_tcp_conversation(
        builder,
        client_port=50000,
        request_seq=1,
        request_payload=lab1a_message(1, 1, b"GET /lab1a"),
        response_payload=lab1a_message(2, 1, b"OK 200"),
    )

    # Stream 1: a second, short TCP conversation.
    add_tcp_conversation(
        builder,
        client_port=50002,
        request_seq=7,
        request_payload=lab1a_message(1, 7, b"second stream"),
        response_payload=lab1a_message(2, 7, b"ok"),
        heartbeat=False,
    )

    # UDP request/response on the same well-known port.
    builder.add_udp(
        client, server, 50001, 9999, lab1a_message(1, 4, b"udp request")
    )
    builder.add_udp(
        server, client, 9999, 50001, lab1a_message(2, 4, b"udp response")
    )

    # Deliberately malformed messages for expert-info demonstration.
    builder.add_udp(client, server, 50003, 9999, b"BAD!\x01\x01\x00\x05\x00\x00")
    builder.add_udp(
        client, server, 50004, 9999, lab1a_message(9, 8, b"unknown type")
    )
    builder.add_udp(
        client,
        server,
        50005,
        9999,
        b"L1A1\x01\x01\x00\x0c\x00\x07abc",
    )
    builder.add_udp(client, server, 50006, 9999, b"L1A1\x01")

    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in builder.frames:
            seconds = int(ts)
            micros = int(round((ts - seconds) * 1_000_000))
            if micros >= 1_000_000:
                seconds += 1
                micros -= 1_000_000
            handle.write(
                struct.pack("<IIII", seconds, micros, len(frame), len(frame))
            )
            handle.write(frame)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        default="lab1a_demo.pcap",
        help="output pcap path (default: lab1a_demo.pcap)",
    )
    args = parser.parse_args()
    path = build_demo_capture(args.out)
    print(f"wrote {path} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
