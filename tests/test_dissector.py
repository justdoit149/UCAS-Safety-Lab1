"""Unit tests for the M2 link/network/transport dissector."""

from __future__ import annotations

import random
import socket
import struct
import unittest

from app.core.dissector import DLT_EN10MB, DLT_NULL, DLT_RAW, dissect
from app.core.models import Field, Packet

SRC_MAC = bytes.fromhex("001122334455")
DST_MAC = bytes.fromhex("66778899aabb")
IP_SRC = socket.inet_aton("192.168.1.10")
IP_DST = socket.inet_aton("93.184.216.34")


def eth_header(ethertype: int = 0x0800) -> bytes:
    return DST_MAC + SRC_MAC + struct.pack("!H", ethertype)


def ipv4_header(
    proto: int,
    payload_len: int,
    src: bytes = IP_SRC,
    dst: bytes = IP_DST,
    ihl: int = 5,
    flags_frag: int = 0x4000,
    options: bytes = b"",
    total_len: int | None = None,
) -> bytes:
    header_len = ihl * 4
    if total_len is None:
        total_len = header_len + payload_len
    first = 0x40 | ihl
    header = struct.pack(
        "!BBHHHBBH4s4s",
        first,
        0,
        total_len,
        0x1234,
        flags_frag,
        64,
        proto,
        0,
        src,
        dst,
    )
    if options:
        header += options
    return header


def ipv6_header(next_header: int, payload_len: int) -> bytes:
    src = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    dst = socket.inet_pton(socket.AF_INET6, "2001:db8::2")
    return struct.pack("!IHBB16s16s", 0x60000000, payload_len, next_header, 64,
                       src, dst)


def tcp_header(
    sport: int = 12345,
    dport: int = 80,
    flags: int = 0x02,
    seq: int = 1,
    ack: int = 0,
    data_offset_words: int = 5,
    options: bytes = b"",
) -> bytes:
    return struct.pack(
        "!HHIIBBHHH",
        sport,
        dport,
        seq,
        ack,
        data_offset_words << 4,
        flags,
        64240,
        0,
        0,
    ) + options


def udp_header(sport: int = 5353, dport: int = 53, payload: bytes = b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def field_of(packet: Packet, layer_name: str, field_name: str) -> Field:
    layer = next(layer for layer in packet.layers if layer.name == layer_name)
    return next(field for field in layer.fields if field.name == field_name)


def all_fields(fields: list[Field]):
    for item in fields:
        yield item
        yield from all_fields(item.children)


class DissectorTest(unittest.TestCase):
    def test_ethernet_ipv4_tcp(self) -> None:
        payload = b"GET / HTTP/1.1\r\n\r\n"
        raw = (
            eth_header()
            + ipv4_header(6, 20 + len(payload))
            + tcp_header()
            + payload
        )
        packet = dissect(1, 0.0, raw, len(raw), DLT_EN10MB)

        self.assertEqual(packet.proto_label, "TCP")
        self.assertEqual(packet.transport, "TCP")
        self.assertEqual(packet.sport, 12345)
        self.assertEqual(packet.dport, 80)
        self.assertEqual(packet.tcp_flags, "SYN")
        self.assertEqual(packet.ip_src, "192.168.1.10")
        self.assertEqual(packet.ip_dst, "93.184.216.34")
        self.assertEqual(packet.src, "00:11:22:33:44:55")
        self.assertEqual(packet.dst, "66:77:88:99:aa:bb")
        self.assertEqual([layer.name for layer in packet.layers],
                         ["Ethernet", "IPv4", "TCP"])

        sport_field = field_of(packet, "TCP", "Source Port")
        self.assertEqual((sport_field.offset, sport_field.length), (34, 2))
        self.assertIn("12345", packet.summary)
        self.assertIn("80", packet.summary)
        self.assertIn("SYN", packet.summary)
        self.assertFalse(packet.truncated)

    def test_tcp_syn_ack_flags_and_options(self) -> None:
        timestamp = struct.pack("!BBII", 8, 10, 111, 222) + b"\x00\x00"
        raw = (
            eth_header()
            + ipv4_header(6, 32 + 4)
            + tcp_header(flags=0x12, ack=99, data_offset_words=8,
                         options=timestamp)
            + b"data"
        )
        packet = dissect(2, 0.0, raw, len(raw), DLT_EN10MB)
        self.assertEqual(packet.tcp_flags, "SYN, ACK")
        self.assertIn("Ack=99", packet.summary)
        options = field_of(packet, "TCP", "Options")
        self.assertEqual(options.offset, 14 + 20 + 20)
        self.assertEqual(options.length, 12)
        self.assertTrue(any(child.name == "Timestamps" for child in options.children))

    def test_ipv4_options_shift_tcp_offset(self) -> None:
        raw = (
            eth_header()
            + ipv4_header(6, 20 + 4, ihl=6, options=b"\x01\x01\x00\x00")
            + tcp_header()
            + b"test"
        )
        packet = dissect(3, 0.0, raw, len(raw), DLT_EN10MB)
        self.assertEqual(packet.sport, 12345)
        self.assertEqual(field_of(packet, "TCP", "Source Port").offset, 14 + 24)
        self.assertEqual(field_of(packet, "IPv4", "Options").length, 4)

    def test_ipv4_udp(self) -> None:
        raw = eth_header() + ipv4_header(17, 8 + 4) + udp_header(payload=b"ping")
        packet = dissect(4, 0.0, raw, len(raw), DLT_EN10MB)
        self.assertEqual(packet.proto_label, "UDP")
        self.assertEqual(packet.transport, "UDP")
        self.assertEqual(packet.sport, 5353)
        self.assertEqual(packet.dport, 53)
        self.assertIn("Len=4", packet.summary)

    def test_icmp_echo(self) -> None:
        icmp = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 7) + b"abcdef"
        raw = eth_header() + ipv4_header(1, len(icmp)) + icmp
        packet = dissect(5, 0.0, raw, len(raw), DLT_EN10MB)
        self.assertEqual(packet.proto_label, "ICMP")
        self.assertEqual(packet.transport, "ICMP")
        self.assertIn("Echo (ping) request", packet.summary)
        self.assertIn("seq=7", packet.summary)
        self.assertEqual(field_of(packet, "ICMP", "Sequence").offset, 14 + 20 + 6)

    def test_arp_request(self) -> None:
        arp = (
            struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
            + SRC_MAC
            + IP_SRC
            + b"\x00" * 6
            + socket.inet_aton("192.168.1.1")
        )
        raw = eth_header(0x0806) + arp
        packet = dissect(6, 0.0, raw, len(raw), DLT_EN10MB)
        self.assertEqual(packet.proto_label, "ARP")
        self.assertEqual(packet.ip_src, "192.168.1.10")
        self.assertEqual(packet.ip_dst, "192.168.1.1")
        self.assertIn("Who has 192.168.1.1?", packet.summary)
        self.assertEqual(field_of(packet, "ARP", "Opcode").offset, 14 + 6)

    def test_vlan_tag(self) -> None:
        raw = (
            DST_MAC
            + SRC_MAC
            + struct.pack("!HHH", 0x8100, 0x0064, 0x0800)
            + ipv4_header(6, 24)
            + tcp_header()
        )
        packet = dissect(7, 0.0, raw, len(raw), DLT_EN10MB)
        self.assertEqual(
            [layer.name for layer in packet.layers],
            ["Ethernet", "802.1Q VLAN", "IPv4", "TCP"],
        )
        self.assertEqual(field_of(packet, "TCP", "Source Port").offset, 14 + 4 + 20)

    def test_ipv6_tcp(self) -> None:
        raw = eth_header(0x86DD) + ipv6_header(6, 24) + tcp_header()
        packet = dissect(8, 0.0, raw, len(raw), DLT_EN10MB)
        self.assertEqual(packet.proto_label, "TCP")
        self.assertEqual(packet.ip_src, "2001:db8::1")
        self.assertEqual(packet.ip_dst, "2001:db8::2")
        self.assertEqual(field_of(packet, "TCP", "Source Port").offset, 14 + 40)

    def test_ipv6_hop_by_hop_then_tcp(self) -> None:
        ext = bytes([6, 0]) + b"\x00" * 6
        raw = (
            eth_header(0x86DD)
            + ipv6_header(0, len(ext) + 24)
            + ext
            + tcp_header()
        )
        packet = dissect(9, 0.0, raw, len(raw), DLT_EN10MB)
        self.assertEqual(
            [layer.name for layer in packet.layers],
            ["Ethernet", "IPv6", "IPv6 Hop-by-Hop Options", "TCP"],
        )
        self.assertEqual(
            field_of(packet, "TCP", "Source Port").offset, 14 + 40 + 8
        )

    def test_icmpv6_echo(self) -> None:
        icmp = struct.pack("!BBHHH", 128, 0, 0, 0xABCD, 2) + b"hello"
        raw = eth_header(0x86DD) + ipv6_header(58, len(icmp)) + icmp
        packet = dissect(10, 0.0, raw, len(raw), DLT_EN10MB)
        self.assertEqual(packet.proto_label, "ICMPv6")
        self.assertEqual(packet.transport, "ICMPv6")
        self.assertIn("Echo (ping) request", packet.summary)
        self.assertIn("id=0xabcd", packet.summary)

    def test_null_loopback(self) -> None:
        raw = (
            struct.pack("<I", 2)
            + ipv4_header(6, 24)
            + tcp_header()
        )
        packet = dissect(11, 0.0, raw, len(raw), DLT_NULL)
        self.assertEqual(
            [layer.name for layer in packet.layers],
            ["Null/Loopback", "IPv4", "TCP"],
        )
        self.assertEqual(packet.ip_src, "192.168.1.10")
        self.assertEqual(field_of(packet, "Null/Loopback", "Family").offset, 0)

    def test_raw_ip(self) -> None:
        raw = ipv4_header(6, 24) + tcp_header()
        packet = dissect(12, 0.0, raw, len(raw), DLT_RAW)
        self.assertEqual(packet.proto_label, "TCP")
        self.assertEqual(packet.sport, 12345)
        self.assertIn("Raw IP", [layer.name for layer in packet.layers])

    def test_unknown_ethertype(self) -> None:
        raw = eth_header(0x1234) + b"\x01\x02\x03"
        packet = dissect(13, 0.0, raw, len(raw), DLT_EN10MB)
        self.assertEqual(packet.proto_label, "EtherType 0x1234")
        self.assertEqual([layer.name for layer in packet.layers][-1], "Payload")

    def test_unknown_linktype(self) -> None:
        packet = dissect(14, 0.0, b"\x00\x01\x02", 3, 99)
        self.assertEqual(packet.proto_label, "LINKTYPE 99")
        self.assertEqual(packet.layers[0].name, "Link type 99")

    def test_truncated_ethernet(self) -> None:
        packet = dissect(15, 0.0, b"\x00" * 7, 7, DLT_EN10MB)
        self.assertTrue(packet.truncated)
        self.assertEqual(packet.proto_label, "Ethernet")
        self.assertIn("truncated", packet.summary.lower())

    def test_truncated_ipv4(self) -> None:
        raw = eth_header() + b"\x45\x00\x00"
        packet = dissect(16, 0.0, raw, len(raw), DLT_EN10MB)
        self.assertTrue(packet.truncated)
        self.assertEqual(packet.proto_label, "IPv4")
        self.assertIn("truncated", packet.summary.lower())

    def test_truncated_tcp_does_not_crash(self) -> None:
        raw = eth_header() + ipv4_header(6, 10) + b"\x00" * 10
        packet = dissect(17, 0.0, raw, len(raw), DLT_EN10MB)
        self.assertTrue(packet.truncated)
        self.assertEqual(packet.proto_label, "TCP")

    def test_malformed_tcp_data_offset(self) -> None:
        raw = eth_header() + ipv4_header(6, 24) + tcp_header(data_offset_words=0)
        packet = dissect(18, 0.0, raw, len(raw), DLT_EN10MB)
        self.assertTrue(packet.truncated)
        self.assertEqual(packet.proto_label, "TCP")

    def test_all_field_offsets_are_inside_capture(self) -> None:
        payload = b"x" * 100
        timestamp = struct.pack("!BBII", 8, 10, 111, 222)
        raw = (
            eth_header()
            + ipv4_header(6, 28 + len(payload), ihl=6,
                          options=b"\x01\x01\x00\x00")
            + tcp_header(data_offset_words=7, options=timestamp)
            + payload
        )
        packet = dissect(19, 0.0, raw, len(raw), DLT_EN10MB)
        for layer in packet.layers:
            self.assertGreaterEqual(layer.offset, 0)
            self.assertGreaterEqual(layer.length, 0)
            for field in all_fields(layer.fields):
                self.assertGreaterEqual(field.offset, 0, field.name)
                self.assertGreaterEqual(field.length, 0, field.name)
                self.assertLessEqual(
                    field.offset + field.length,
                    len(raw),
                    f"{layer.name}/{field.name} exceeds capture",
                )

    def test_original_length_larger_than_capture_is_marked(self) -> None:
        raw = eth_header() + ipv4_header(17, 8) + udp_header()
        packet = dissect(20, 0.0, raw, len(raw) + 100, DLT_EN10MB)
        self.assertTrue(packet.truncated)
        self.assertIn("[truncated]", packet.summary)

    def test_random_malformed_frames_never_crash_or_escape_capture(self) -> None:
        rng = random.Random(0xC0FFEE)
        linktypes = [DLT_NULL, DLT_EN10MB, DLT_RAW, 99]
        for iteration in range(1000):
            length = rng.randrange(0, 220)
            raw = bytes(rng.getrandbits(8) for _ in range(length))
            linktype = rng.choice(linktypes)
            with self.subTest(iteration=iteration, length=length, linktype=linktype):
                packet = dissect(
                    iteration + 1,
                    float(iteration),
                    raw,
                    len(raw) + rng.randrange(0, 40),
                    linktype,
                )
                for layer in packet.layers:
                    for field in all_fields(layer.fields):
                        self.assertGreaterEqual(field.offset, 0, field.name)
                        self.assertGreaterEqual(field.length, 0, field.name)
                        self.assertLessEqual(
                            field.offset + field.length,
                            len(raw),
                            f"{layer.name}/{field.name} exceeds capture: "
                            f"{raw.hex()}",
                        )


if __name__ == "__main__":
    unittest.main()
