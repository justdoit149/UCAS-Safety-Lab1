"""Tests for BPF preset translation and the display-filter grammar."""

from __future__ import annotations

import unittest

from app.core.filtering import (
    CaptureFilterHint,
    FilterSyntaxError,
    compile_display_filter,
    resolve_capture_filter,
)
from app.core.models import Packet


def make_packet(
    *,
    transport: str = "TCP",
    ip_version: int = 4,
    ip_src: str = "192.168.1.10",
    ip_dst: str = "93.184.216.34",
    sport: int = 12345,
    dport: int = 80,
    app: str = "",
    proto_label: str | None = None,
) -> Packet:
    return Packet(
        index=1,
        ts=0.0,
        caplen=0,
        orig_len=0,
        raw=b"",
        linktype=1,
        ip_src=ip_src,
        ip_dst=ip_dst,
        ip_version=ip_version,
        sport=sport,
        dport=dport,
        transport=transport,
        proto_label=proto_label or transport,
        app=app,
    )


def matches(expression: str, packet: Packet) -> bool:
    return compile_display_filter(expression).matches(packet)


class CaptureFilterPresetTests(unittest.TestCase):
    def test_empty_and_no_filter(self) -> None:
        self.assertEqual(resolve_capture_filter(""), "")
        self.assertEqual(resolve_capture_filter("   "), "")
        self.assertEqual(resolve_capture_filter("（不过滤）"), "")

    def test_friendly_names_are_translated(self) -> None:
        self.assertEqual(
            resolve_capture_filter("HTTP"),
            "tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 8888",
        )
        self.assertEqual(
            resolve_capture_filter("HTTPS"),
            "tcp port 443 or tcp port 8443",
        )
        self.assertEqual(
            resolve_capture_filter("DNS"),
            "udp port 53 or tcp port 53",
        )

    def test_bpf_text_is_passed_through(self) -> None:
        self.assertEqual(resolve_capture_filter("tcp port 80"), "tcp port 80")
        self.assertEqual(
            resolve_capture_filter("host 192.168.1.1 and udp"),
            "host 192.168.1.1 and udp",
        )

    def test_display_only_words_raise_hint(self) -> None:
        for value in ("http", "https", "dns", "tls", "TLS"):
            with self.subTest(value=value):
                with self.assertRaises(CaptureFilterHint):
                    resolve_capture_filter(value)


class DisplayFilterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tcp80 = make_packet(dport=80, sport=50000)
        self.tcp443 = make_packet(dport=443, sport=50001)
        self.udp53 = make_packet(
            transport="UDP", sport=50002, dport=53, proto_label="UDP"
        )
        self.udp123 = make_packet(
            transport="UDP", sport=50003, dport=123, proto_label="UDP"
        )
        self.icmp4 = make_packet(
            transport="ICMP", sport=0, dport=0, proto_label="ICMP"
        )
        self.icmp6 = make_packet(
            transport="ICMPv6",
            ip_version=6,
            ip_src="2001:db8::1",
            ip_dst="2001:db8::2",
            sport=0,
            dport=0,
            proto_label="ICMPv6",
        )
        self.arp = make_packet(
            transport="ARP",
            ip_src="192.168.1.10",
            ip_dst="192.168.1.1",
            sport=0,
            dport=0,
            proto_label="ARP",
        )
        self.tcp6 = make_packet(
            ip_version=6,
            ip_src="2001:db8::1",
            ip_dst="2001:db8::2",
            dport=443,
        )
        self.http = make_packet(app="HTTP", dport=80)
        self.tls = make_packet(app="TLS", dport=443)
        self.dns = make_packet(app="DNS", transport="UDP", dport=53,
                               proto_label="UDP")

    def test_acceptance_protocol_expressions(self) -> None:
        self.assertTrue(matches("http", self.http))
        self.assertFalse(matches("http", self.tcp80))
        self.assertTrue(matches("tcp", self.tcp80))
        self.assertTrue(matches("tcp", self.http))
        self.assertTrue(matches("udp", self.udp53))
        self.assertTrue(matches("icmp", self.icmp4))
        self.assertFalse(matches("icmp", self.icmp6))
        self.assertTrue(matches("icmp6", self.icmp6))
        self.assertTrue(matches("ipv4", self.tcp80))
        self.assertFalse(matches("ipv4", self.tcp6))
        self.assertTrue(matches("ipv6", self.tcp6))
        self.assertTrue(matches("arp", self.arp))
        self.assertTrue(matches("https", self.tls))
        self.assertTrue(matches("tls", self.tls))
        self.assertTrue(matches("dns", self.dns))

    def test_aliases(self) -> None:
        for expression in ("ip", "ipv4"):
            self.assertTrue(matches(expression, self.tcp80))
            self.assertFalse(matches(expression, self.tcp6))
        for expression in ("ipv6", "ip6"):
            self.assertTrue(matches(expression, self.tcp6))
            self.assertFalse(matches(expression, self.tcp80))
        for expression in ("https", "tls"):
            self.assertTrue(matches(expression, self.tls))

    def test_acceptance_logical_expressions(self) -> None:
        self.assertTrue(matches("tcp and port 80", self.tcp80))
        self.assertFalse(matches("tcp and port 80", self.tcp443))
        self.assertFalse(matches("tcp and port 80", self.udp53))
        self.assertTrue(matches("http and tcp", self.http))
        self.assertFalse(matches("http and tcp", self.tls))

        expression = "(tcp or udp) and not port 53"
        self.assertTrue(matches(expression, self.tcp80))
        self.assertTrue(matches(expression, self.udp123))
        self.assertFalse(matches(expression, self.udp53))
        self.assertFalse(matches(expression, self.icmp4))

        self.assertTrue(matches("ipv4 and icmp", self.icmp4))
        self.assertFalse(matches("ipv4 and icmp", self.icmp6))
        self.assertTrue(matches("ipv6 or arp", self.tcp6))
        self.assertTrue(matches("ipv6 or arp", self.arp))
        self.assertFalse(matches("ipv6 or arp", self.tcp80))

        expression = "not (http or tls)"
        self.assertTrue(matches(expression, self.tcp80))
        self.assertTrue(matches(expression, self.udp53))
        self.assertFalse(matches(expression, self.http))
        self.assertFalse(matches(expression, self.tls))

    def test_precedence(self) -> None:
        # and binds tighter than or.
        expression = "tcp or udp and port 53"
        self.assertTrue(matches(expression, self.tcp80))
        self.assertTrue(matches(expression, self.udp53))
        self.assertFalse(matches(expression, self.udp123))

        expression = "not tcp and port 53"
        self.assertTrue(matches(expression, self.udp53))
        self.assertFalse(matches(expression, self.tcp80))

    def test_port_and_host_predicates(self) -> None:
        self.assertTrue(matches("port 80", self.tcp80))
        self.assertTrue(matches("src port 50000", self.tcp80))
        self.assertFalse(matches("dst port 50000", self.tcp80))
        self.assertTrue(matches("host 192.168.1.10", self.tcp80))
        self.assertTrue(matches("host 93.184.216.34", self.tcp80))
        self.assertFalse(matches("host 10.0.0.1", self.tcp80))
        self.assertTrue(matches("src host 192.168.1.10", self.tcp80))
        self.assertFalse(matches("dst host 192.168.1.10", self.tcp80))
        self.assertTrue(matches("dst host 93.184.216.34", self.tcp80))

    def test_ipv6_host_is_normalized(self) -> None:
        self.assertTrue(
            matches("host 2001:0db8:0:0:0:0:0:1", self.tcp6)
        )
        self.assertTrue(matches("src host 2001:db8::1", self.tcp6))
        self.assertTrue(matches("dst host 2001:db8::2", self.tcp6))

    def test_case_insensitive(self) -> None:
        self.assertTrue(matches("TCP AND PORT 80", self.tcp80))
        self.assertTrue(matches("Http", self.http))
        self.assertTrue(matches("NOT (HTTP OR TLS)", self.tcp80))

    def test_syntax_errors_report_position(self) -> None:
        bad_expressions = [
            "",
            "tcp and",
            "or tcp",
            "port",
            "port 70000",
            "port not-a-number",
            "host not-an-ip",
            "host",
            "src",
            "src tcp",
            "(tcp",
            "tcp)",
            "tcp port 80",
            "unknown",
            "tcp and )",
        ]
        for expression in bad_expressions:
            with self.subTest(expression=expression):
                with self.assertRaises(FilterSyntaxError) as context:
                    compile_display_filter(expression)
                self.assertGreaterEqual(context.exception.position, 0)
                self.assertIn("位置", str(context.exception))

    def test_empty_expression_position_is_zero(self) -> None:
        with self.assertRaises(FilterSyntaxError) as context:
            compile_display_filter("   ")
        self.assertEqual(context.exception.position, 0)

    def test_matches_never_raises_on_bad_packet_fields(self) -> None:
        packet = make_packet(ip_src="not-an-ip")
        self.assertFalse(matches("host 192.168.1.1", packet))


if __name__ == "__main__":
    unittest.main()
