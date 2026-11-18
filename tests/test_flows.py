"""Tests for canonical flow keys and bidirectional flow tracking."""

from __future__ import annotations

import unittest

from app.core.flowkey import endpoint_text, flow_key_for
from app.core.models import Packet
from app.services.flows import FlowManager
from app.services.process_map import ProcessInfo


def packet(
    index: int,
    ts: float,
    *,
    src: str = "10.0.0.1",
    sport: int = 40000,
    dst: str = "10.0.0.2",
    dport: int = 80,
    transport: str = "TCP",
    flags: str = "",
    app: str = "",
    length: int = 100,
) -> Packet:
    return Packet(
        index=index,
        ts=ts,
        caplen=length,
        orig_len=length,
        raw=b"",
        linktype=1,
        ip_src=src,
        ip_dst=dst,
        sport=sport,
        dport=dport,
        transport=transport,
        tcp_flags=flags,
        app=app,
        proto_label=app or transport,
    )


class FlowKeyTests(unittest.TestCase):
    def test_key_is_direction_independent(self) -> None:
        forward = flow_key_for("TCP", "10.0.0.1", 40000, "10.0.0.2", 80)
        backward = flow_key_for("TCP", "10.0.0.2", 80, "10.0.0.1", 40000)
        self.assertIsNotNone(forward)
        self.assertEqual(forward, backward)
        self.assertEqual(forward[0], "TCP")

    def test_ipv6_spellings_share_one_key(self) -> None:
        first = flow_key_for(
            "TCP", "2001:db8::1", 40000, "2001:db8::2", 443
        )
        second = flow_key_for(
            "TCP", "2001:0db8:0:0:0:0:0:2", 443,
            "2001:0db8:0:0:0:0:0:1", 40000,
        )
        self.assertEqual(first, second)

    def test_non_transport_and_bad_addresses(self) -> None:
        self.assertIsNone(flow_key_for("ICMP", "10.0.0.1", 0, "10.0.0.2", 0))
        self.assertIsNone(flow_key_for("TCP", "not-an-ip", 1, "10.0.0.2", 2))
        self.assertIsNone(flow_key_for("TCP", "", 1, "10.0.0.2", 2))
        self.assertIsNone(flow_key_for("UDP", "10.0.0.1", 1, "bad", 2))

    def test_endpoint_text(self) -> None:
        self.assertEqual(endpoint_text("10.0.0.1", 80), "10.0.0.1:80")
        self.assertEqual(endpoint_text("2001:db8::1", 53), "[2001:db8::1]:53")

    def test_ipv6_zone_id_is_ignored(self) -> None:
        with_zone = flow_key_for(
            "TCP", "fe80::1%12", 40000, "fe80::2%12", 80
        )
        without_zone = flow_key_for(
            "TCP", "fe80::1", 40000, "fe80::2", 80
        )
        self.assertEqual(with_zone, without_zone)


class FlowManagerTests(unittest.TestCase):
    def test_bidirectional_packets_aggregate(self) -> None:
        manager = FlowManager()
        first = packet(1, 100.0, flags="SYN", length=60)
        second = packet(
            2, 100.5, src="10.0.0.2", sport=80,
            dst="10.0.0.1", dport=40000, flags="ACK",
            app="HTTP", length=500,
        )
        manager.add_packet(first)
        manager.add_packet(second)

        self.assertEqual(len(manager.flows), 1)
        flow = next(iter(manager.flows.values()))
        self.assertIsNotNone(first.flow_key)
        self.assertEqual(first.flow_key, second.flow_key)
        self.assertEqual(flow.packet_count, 2)
        self.assertEqual(flow.byte_count, 560)
        self.assertEqual(flow.first_ts, 100.0)
        self.assertEqual(flow.last_ts, 100.5)
        self.assertEqual(flow.app, "HTTP")
        self.assertEqual(flow.direction_label(first), "A → B")
        self.assertEqual(flow.direction_label(second), "B → A")

    def test_tcp_state_machine(self) -> None:
        manager = FlowManager()
        manager.add_packet(packet(1, 1.0, flags="SYN"))
        flow = next(iter(manager.flows.values()))
        self.assertEqual(flow.state, "SYN_SENT")

        manager.add_packet(packet(
            2, 1.1, src="10.0.0.2", sport=80,
            dst="10.0.0.1", dport=40000, flags="SYN, ACK",
        ))
        self.assertEqual(flow.state, "SYN_RCVD")

        manager.add_packet(packet(3, 1.2, flags="ACK"))
        self.assertEqual(flow.state, "ESTABLISHED")

        manager.add_packet(packet(4, 1.3, flags="FIN, ACK"))
        self.assertEqual(flow.state, "FIN_WAIT")

        manager.add_packet(packet(
            5, 1.4, src="10.0.0.2", sport=80,
            dst="10.0.0.1", dport=40000, flags="FIN, ACK",
        ))
        self.assertEqual(flow.state, "CLOSED")

    def test_rst_closes_immediately(self) -> None:
        manager = FlowManager()
        manager.add_packet(packet(1, 1.0, flags="SYN"))
        manager.add_packet(packet(2, 1.1, flags="RST"))
        self.assertEqual(next(iter(manager.flows.values())).state, "CLOSED")

    def test_udp_expiry_and_reactivation(self) -> None:
        manager = FlowManager()
        manager.add_packet(packet(1, 100.0, transport="UDP", dport=53))
        flow = next(iter(manager.flows.values()))
        self.assertEqual(flow.state, "ACTIVE")

        manager.expire_stale(reference_ts=220.0)
        self.assertEqual(flow.state, "ACTIVE")
        manager.expire_stale(reference_ts=220.1)
        self.assertEqual(flow.state, "EXPIRED")

        manager.add_packet(packet(2, 221.0, transport="UDP", dport=53))
        self.assertEqual(flow.state, "ACTIVE")
        self.assertEqual(flow.packet_count, 2)

    def test_flows_sorted_by_latest_activity(self) -> None:
        manager = FlowManager()
        manager.add_packet(packet(1, 10.0))
        manager.add_packet(packet(
            2, 30.0, dst="10.0.0.3", dport=443,
        ))
        manager.add_packet(packet(3, 20.0))
        flows = manager.flows_sorted(reference_ts=30.0)
        self.assertEqual([flow.last_ts for flow in flows], [30.0, 20.0])
        self.assertEqual(flows[0].dst_port, 443)

    def test_non_ip_packet_is_ignored(self) -> None:
        manager = FlowManager()
        raw = packet(1, 1.0)
        raw.ip_src = ""
        self.assertIsNone(manager.add_packet(raw))
        self.assertEqual(manager.flows, {})
        self.assertIsNone(raw.flow_key)

    def test_process_labels_and_filters(self) -> None:
        manager = FlowManager()
        manager.add_packet(packet(1, 10.0, flags="ACK"))
        manager.add_packet(packet(
            2, 11.0, dst="10.0.0.3", dport=53, transport="UDP",
        ))
        tcp_flow = next(
            flow for flow in manager.flows.values() if flow.protocol == "TCP"
        )
        udp_flow = next(
            flow for flow in manager.flows.values() if flow.protocol == "UDP"
        )
        tcp_flow.proc_src = ProcessInfo(100, "chrome")
        tcp_flow.proc_dst = ProcessInfo(200, "server")
        udp_flow.proc_src = ProcessInfo(300, "dns")
        udp_flow.proc_dst = ProcessInfo(300, "dns")

        self.assertEqual(tcp_flow.process_pids, {100, 200})
        self.assertEqual(tcp_flow.process_label, "chrome(100) ↔ server(200)")
        self.assertEqual(udp_flow.process_pids, {300})
        self.assertEqual(udp_flow.process_label, "dns(300)")
        self.assertEqual(
            [flow.key for flow in manager.flows_for_process(100)],
            [tcp_flow.key],
        )
        self.assertEqual(
            [flow.key for flow in manager.flows_for_process(300)],
            [],
        )
        self.assertEqual(
            [flow.key for flow in manager.flows_for_process(
                300, tcp_only=False
            )],
            [udp_flow.key],
        )

    def test_process_mapping_is_not_erased_when_connection_closes(self) -> None:
        class FakeMap:
            def __init__(self):
                self.mapping = {
                    ("10.0.0.1", 40000): ProcessInfo(111, "client"),
                }

            def lookup(self, ip, port):
                return self.mapping.get((ip, port))

        manager = FlowManager()
        manager.add_packet(packet(1, 10.0, flags="ACK"))
        flow = next(iter(manager.flows.values()))
        fake = FakeMap()
        manager.apply_process_map(fake)
        self.assertEqual(flow.proc_src, ProcessInfo(111, "client"))
        self.assertIsNone(flow.proc_dst)

        fake.mapping.clear()
        manager.apply_process_map(fake)
        self.assertEqual(flow.proc_src, ProcessInfo(111, "client"))


if __name__ == "__main__":
    unittest.main()
