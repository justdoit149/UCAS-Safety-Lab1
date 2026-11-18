"""M1 smoke tests for the Npcap ctypes layer."""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app.core.dissector import dissect  # noqa: E402
from app.core.pcap_driver import (  # noqa: E402
    NpcapNotFoundError,
    PcapError,
    PcapHandle,
    libpcap_version,
    list_devices,
)


class PcapDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            cls.devices = list_devices()
            cls.version = libpcap_version()
        except NpcapNotFoundError as exc:
            raise unittest.SkipTest(str(exc))

    def test_libpcap_version(self) -> None:
        self.assertTrue(self.version)
        self.assertIn("libpcap", self.version.lower())

    def test_devices_have_names(self) -> None:
        self.assertTrue(self.devices)
        for device in self.devices:
            self.assertTrue(device.name)
            self.assertTrue(device.display_name)

    def test_loopback_device_is_flagged(self) -> None:
        loopback = [device for device in self.devices if device.is_loopback]
        if not loopback:
            self.skipTest("当前 Npcap 没有枚举到回环设备")
        self.assertTrue(all("loopback" in device.name.lower() for device in loopback))

    def test_invalid_device_raises(self) -> None:
        with self.assertRaises(PcapError):
            PcapHandle.open_live(
                r"\Device\NPF_ThisDeviceDoesNotExist",
                timeout_ms=10,
            )

    def test_loopback_capture_counts_packets(self) -> None:
        loopback = next((device for device in self.devices if device.is_loopback), None)
        if loopback is None:
            self.skipTest("当前 Npcap 没有枚举到回环设备")

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        received: list[bytes] = []

        def serve() -> None:
            try:
                conn, _ = server.accept()
                try:
                    received.append(conn.recv(128))
                finally:
                    conn.close()
            finally:
                server.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()

        payload = b"M1-loopback-test"
        with PcapHandle.open_live(loopback.name, timeout_ms=50) as handle:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                client.sendall(payload)

            deadline = time.time() + 3.0
            captured = 0
            while time.time() < deadline and captured == 0:
                if handle.next_packet() is not None:
                    captured += 1

            received_count, dropped, if_dropped = handle.stats()

        thread.join(timeout=1.0)
        self.assertGreaterEqual(captured, 1, "回环抓包没有读到任何原始帧")
        self.assertGreaterEqual(received_count, 0)
        self.assertGreaterEqual(dropped, 0)
        self.assertGreaterEqual(if_dropped, 0)
        self.assertEqual(received, [payload])

    def test_bpf_filter_accepts_valid_and_rejects_invalid_expression(self) -> None:
        loopback = next((device for device in self.devices if device.is_loopback), None)
        if loopback is None:
            self.skipTest("当前 Npcap 没有枚举到回环设备")

        with PcapHandle.open_live(loopback.name, timeout_ms=10) as handle:
            handle.set_filter("tcp")
            with self.assertRaises(PcapError):
                handle.set_filter("tcp por 80")

    def test_bpf_filter_drops_non_matching_loopback_packets(self) -> None:
        loopback = next((device for device in self.devices if device.is_loopback), None)
        if loopback is None:
            self.skipTest("当前 Npcap 没有枚举到回环设备")

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def serve() -> None:
            try:
                conn, _ = server.accept()
                try:
                    conn.recv(128)
                finally:
                    conn.close()
            finally:
                server.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()

        with PcapHandle.open_live(loopback.name, timeout_ms=50) as handle:
            handle.set_filter(f"tcp port {port}")

            with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                client.sendall(b"M3-bpf-test")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.sendto(b"not-tcp", ("127.0.0.1", port))

            deadline = time.time() + 2.0
            captured: list[tuple] = []
            while time.time() < deadline:
                item = handle.next_packet()
                if item is not None:
                    captured.append(item)

        thread.join(timeout=1.0)
        self.assertGreaterEqual(len(captured), 1, "BPF 过滤后没有抓到 TCP 包")
        for index, (ts, caplen, orig_len, raw) in enumerate(captured, start=1):
            packet = dissect(index, ts, raw, orig_len, handle.datalink)
            self.assertEqual(packet.transport, "TCP", packet.summary)
            self.assertTrue(
                port in (packet.sport, packet.dport),
                f"过滤器漏掉了非目标端口的包: {packet.summary}",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
