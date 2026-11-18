"""M4 tests for HTTP, DNS and TLS identification/parsing."""

from __future__ import annotations

import socket
import struct
import unittest

from app.core.app_protocols import ApplicationContext
from app.core.dissector import DLT_EN10MB, dissect
from app.core.filtering import compile_display_filter
from app.core.models import Field, Packet

SRC_MAC = bytes.fromhex("001122334455")
DST_MAC = bytes.fromhex("66778899aabb")
IP_SRC = socket.inet_aton("192.168.1.10")
IP_DST = socket.inet_aton("93.184.216.34")


def ethernet() -> bytes:
    return DST_MAC + SRC_MAC + struct.pack("!H", 0x0800)


def ipv4(proto: int, payload_len: int,
         src: bytes = IP_SRC, dst: bytes = IP_DST) -> bytes:
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + payload_len,
        0x1234,
        0x4000,
        64,
        proto,
        0,
        src,
        dst,
    )


def tcp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack(
        "!HHIIBBHHH",
        sport,
        dport,
        1,
        1,
        5 << 4,
        0x18,
        64240,
        0,
        0,
    ) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp_frame(sport: int, dport: int, payload: bytes,
              src: bytes = IP_SRC, dst: bytes = IP_DST) -> bytes:
    segment = tcp(sport, dport, payload)
    return ethernet() + ipv4(6, len(segment), src, dst) + segment


def udp_frame(sport: int, dport: int, payload: bytes) -> bytes:
    datagram = udp(sport, dport, payload)
    return ethernet() + ipv4(17, len(datagram)) + datagram


def dissect_frame(raw: bytes, context: ApplicationContext | None = None,
                  index: int = 1) -> Packet:
    return dissect(index, 0.0, raw, len(raw), DLT_EN10MB, context)


def all_fields(fields: list[Field]):
    for item in fields:
        yield item
        yield from all_fields(item.children)


def field_of(packet: Packet, layer_name: str, field_name: str) -> Field:
    layer = next(layer for layer in packet.layers if layer.name == layer_name)
    return next(field for field in layer.fields if field.name == field_name)


def child_value(packet: Packet, layer_name: str, parent_name: str,
                child_name: str) -> str:
    parent = field_of(packet, layer_name, parent_name)
    return next(child.value for child in parent.children if child.name == child_name)


def assert_fields_inside(test: unittest.TestCase, packet: Packet) -> None:
    for layer in packet.layers:
        test.assertGreaterEqual(layer.offset, 0)
        test.assertGreaterEqual(layer.length, 0)
        for field in all_fields(layer.fields):
            test.assertGreaterEqual(field.offset, 0, field.name)
            test.assertGreaterEqual(field.length, 0, field.name)
            test.assertLessEqual(
                field.offset + field.length,
                len(packet.raw),
                f"{layer.name}/{field.name} exceeds capture",
            )


def dns_query(name: str = "example.com", qtype: int = 1,
              txid: int = 0x1A2B) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode()
                      for part in name.split("."))
    question = labels + b"\x00" + struct.pack("!HH", qtype, 1)
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    return header + question


def dns_response(name: str = "example.com", rtype: int = 28,
                 rdata: bytes = socket.inet_pton(socket.AF_INET6, "2001:db8::9"),
                 txid: int = 0x1A2B) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode()
                      for part in name.split("."))
    question = labels + b"\x00" + struct.pack("!HH", rtype, 1)
    answer = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", rtype, 1, 60, len(rdata))
        + rdata
    )
    header = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    return header + question + answer


def tls_client_hello(host: str = "www.example.com") -> bytes:
    host_bytes = host.encode()
    sni_data = struct.pack("!HBH", 3 + len(host_bytes), 0, len(host_bytes)) + host_bytes
    sni = struct.pack("!HH", 0, len(sni_data)) + sni_data

    alpn_data = struct.pack("!H", 4 + len(b"http/1.1")) + (
        b"\x02h2\x08http/1.1"
    )
    alpn = struct.pack("!HH", 16, len(alpn_data)) + alpn_data

    versions_data = b"\x04\x0a\x0a\x03\x04"
    versions = struct.pack("!HH", 43, len(versions_data)) + versions_data

    extensions = sni + alpn + versions
    body = (
        b"\x03\x03"
        + b"\x11" * 32
        + b"\x00"
        + struct.pack("!H", 6)
        + b"\x0a\x0a\x13\x01\x13\x02"
        + b"\x01\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


class HttpTests(unittest.TestCase):
    def request_packet(self) -> Packet:
        payload = (
            b"GET /index.html?q=1 HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"User-Agent: lab1/1.0\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 4\r\n"
            b"\r\n"
            b"body"
        )
        return dissect_frame(tcp_frame(50000, 80, payload))

    def test_http_request_fields_and_summary(self) -> None:
        packet = self.request_packet()
        self.assertEqual(packet.app, "HTTP")
        self.assertEqual(packet.proto_label, "HTTP")
        self.assertEqual(packet.transport, "TCP")
        self.assertEqual(packet.summary, "GET /index.html?q=1 HTTP/1.1")
        self.assertEqual([layer.name for layer in packet.layers],
                         ["Ethernet", "IPv4", "TCP", "HTTP"])
        self.assertEqual(field_of(packet, "HTTP", "Request Method").value, "GET")
        self.assertEqual(field_of(packet, "HTTP", "Request URI").value,
                         "/index.html?q=1")
        self.assertEqual(field_of(packet, "HTTP", "Request Version").value,
                         "HTTP/1.1")
        self.assertEqual(child_value(packet, "HTTP", "Headers", "Host"),
                         "example.com")
        self.assertEqual(child_value(packet, "HTTP", "Headers", "User-Agent"),
                         "lab1/1.0")
        self.assertEqual(field_of(packet, "HTTP", "Body").length, 4)
        assert_fields_inside(self, packet)

    def test_http_response_on_nonstandard_port(self) -> None:
        payload = (
            b"HTTP/1.1 404 Not Found\r\n"
            b"Content-Length: 0\r\n"
            b"\r\n"
        )
        packet = dissect_frame(tcp_frame(51000, 51001, payload))
        self.assertEqual(packet.app, "HTTP")
        self.assertEqual(packet.summary, "HTTP/1.1 404 Not Found")
        self.assertEqual(field_of(packet, "HTTP", "Status Code").value, "404")
        self.assertEqual(field_of(packet, "HTTP", "Reason Phrase").value,
                         "Not Found")

    def test_http_response_without_request_line_uses_flow_context(self) -> None:
        context = ApplicationContext()
        request = dissect_frame(
            tcp_frame(52000, 52001, b"POST /upload HTTP/1.1\r\nHost: x\r\n\r\n"),
            context,
        )
        self.assertEqual(request.app, "HTTP")

        continuation = dissect_frame(
            tcp_frame(52001, 52000, b"continued-body", IP_DST, IP_SRC),
            context,
            index=2,
        )
        self.assertEqual(continuation.app, "HTTP")
        self.assertEqual(continuation.proto_label, "HTTP")
        self.assertIn("HTTP data", continuation.summary)

        without_context = dissect_frame(
            tcp_frame(52001, 52000, b"continued-body"),
            index=3,
        )
        self.assertEqual(without_context.app, "")
        self.assertEqual(without_context.proto_label, "TCP")

    def test_non_http_payload_on_port_80_stays_tcp(self) -> None:
        packet = dissect_frame(tcp_frame(50000, 80, b"\x00\x01\x02\x03"))
        self.assertEqual(packet.app, "")
        self.assertEqual(packet.proto_label, "TCP")

    def test_http_display_filter_integration(self) -> None:
        packet = self.request_packet()
        self.assertTrue(compile_display_filter("http").matches(packet))
        self.assertTrue(compile_display_filter("tcp").matches(packet))
        self.assertTrue(compile_display_filter("http and tcp").matches(packet))
        self.assertFalse(compile_display_filter("https").matches(packet))
        self.assertFalse(compile_display_filter("not (http or tls)").matches(packet))


class DnsTests(unittest.TestCase):
    def test_dns_udp_query(self) -> None:
        packet = dissect_frame(udp_frame(53000, 53, dns_query()))
        self.assertEqual(packet.app, "DNS")
        self.assertEqual(packet.proto_label, "DNS")
        self.assertEqual(packet.summary, "Standard query 0x1a2b A example.com")
        self.assertEqual(field_of(packet, "DNS", "Transaction ID").value, "0x1a2b")
        self.assertEqual(field_of(packet, "DNS", "Questions Count").value, "1")
        questions = field_of(packet, "DNS", "Questions")
        name = next(child.value for child in questions.children[0].children
                    if child.name == "Name")
        self.assertEqual(name, "example.com")
        assert_fields_inside(self, packet)

    def test_dns_udp_response_compression_and_aaaa(self) -> None:
        packet = dissect_frame(udp_frame(53, 53000, dns_response()))
        self.assertEqual(packet.app, "DNS")
        self.assertIn("Standard query response", packet.summary)
        self.assertIn("AAAA example.com", packet.summary)
        answers = field_of(packet, "DNS", "Answers")
        self.assertEqual(len(answers.children), 1)
        answer = answers.children[0]
        self.assertEqual(answer.children[0].name, "Name")
        address = next(child.value for child in answer.children
                       if child.name == "Address")
        self.assertEqual(address, "2001:db8::9")
        assert_fields_inside(self, packet)

    def test_dns_tcp_length_prefix(self) -> None:
        message = dns_query()
        payload = struct.pack("!H", len(message)) + message
        packet = dissect_frame(tcp_frame(54000, 53, payload))
        self.assertEqual(packet.app, "DNS")
        self.assertEqual(field_of(packet, "DNS", "TCP Message Length").value,
                         str(len(message)))
        self.assertIn("A example.com", packet.summary)
        self.assertTrue(compile_display_filter("dns").matches(packet))

    def test_non_dns_payload_on_port_53_stays_udp(self) -> None:
        packet = dissect_frame(udp_frame(53000, 53, b"ping"))
        self.assertEqual(packet.app, "")
        self.assertEqual(packet.proto_label, "UDP")


class TlsTests(unittest.TestCase):
    def test_client_hello_sni_alpn_and_supported_versions(self) -> None:
        packet = dissect_frame(tcp_frame(55000, 443, tls_client_hello()))
        self.assertEqual(packet.app, "TLS")
        self.assertEqual(packet.proto_label, "TLS")
        self.assertEqual(packet.summary, "Client Hello (SNI=www.example.com)")
        self.assertEqual(field_of(packet, "TLS", "Content Type").value,
                         "22 (Handshake)")
        self.assertEqual(field_of(packet, "TLS", "Handshake Type").value,
                         "Client Hello")
        self.assertEqual(field_of(packet, "TLS", "Client Version").value,
                         "TLS 1.2")

        cipher_suites = field_of(packet, "TLS", "Cipher Suites")
        values = [child.value for child in cipher_suites.children]
        self.assertEqual(len(values), 2)
        self.assertTrue(any("TLS_AES_128_GCM_SHA256" in value for value in values))
        self.assertFalse(any("0x0a0a" in value for value in values))

        extensions = field_of(packet, "TLS", "Extensions")
        names = [child.name for child in extensions.children]
        self.assertIn("server_name", names)
        self.assertIn("application_layer_protocol_negotiation", names)
        self.assertIn("supported_versions", names)

        sni_ext = next(child for child in extensions.children
                       if child.name == "server_name")
        self.assertEqual(sni_ext.children[0].value, "www.example.com")
        alpn_ext = next(
            child for child in extensions.children
            if child.name == "application_layer_protocol_negotiation"
        )
        self.assertIn("h2", alpn_ext.value)
        versions_ext = next(child for child in extensions.children
                            if child.name == "supported_versions")
        self.assertIn("TLS 1.3", versions_ext.value)
        self.assertNotIn("0x0a0a", versions_ext.value)
        assert_fields_inside(self, packet)

    def test_tls_application_data_on_https_port(self) -> None:
        record = b"\x17\x03\x03\x00\x05hello"
        packet = dissect_frame(tcp_frame(443, 55000, record))
        self.assertEqual(packet.app, "TLS")
        self.assertEqual(packet.summary, "TLS Application Data  Len=5")
        self.assertTrue(compile_display_filter("https").matches(packet))
        self.assertTrue(compile_display_filter("tls").matches(packet))
        self.assertFalse(compile_display_filter("http").matches(packet))

    def test_client_hello_on_nonstandard_port(self) -> None:
        packet = dissect_frame(tcp_frame(56000, 56001, tls_client_hello()))
        self.assertEqual(packet.app, "TLS")
        self.assertEqual(packet.summary, "Client Hello (SNI=www.example.com)")

    def test_non_tls_payload_on_443_stays_tcp(self) -> None:
        packet = dissect_frame(tcp_frame(56000, 443, b"not-a-tls-record"))
        self.assertEqual(packet.app, "")
        self.assertEqual(packet.proto_label, "TCP")


class MalformedApplicationTests(unittest.TestCase):
    def test_malformed_payloads_do_not_crash_and_fields_stay_inside(self) -> None:
        payloads = [
            b"GET",
            b"GET / HTTP/1.1\r\nHost",
            b"HTTP/1.1 200",
            b"\x16\x03\x03\xff\xff",
            b"\x16\x03\x03\x00\x04\x01\x00\x00",
            b"\x00" * 12,
            b"\xff" * 40,
        ]
        index = 0
        for payload in payloads:
            for sport, dport in ((40000, 80), (40000, 53), (40000, 443)):
                index += 1
                with self.subTest(payload=payload[:8], dport=dport):
                    packet = dissect_frame(tcp_frame(sport, dport, payload),
                                           index=index)
                    assert_fields_inside(self, packet)


if __name__ == "__main__":
    unittest.main()
