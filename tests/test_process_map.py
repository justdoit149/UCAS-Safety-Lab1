"""Tests for the psutil-backed local endpoint to process mapping."""

from __future__ import annotations

import unittest
from unittest.mock import patch

import psutil

from app.services.process_map import ProcessInfo, ProcessMap


class FakeConnection:
    def __init__(self, laddr, pid, status=psutil.CONN_ESTABLISHED):
        self.laddr = laddr
        self.pid = pid
        self.status = status


def names(mapping):
    return lambda pid: mapping.get(pid)


class ProcessMapTests(unittest.TestCase):
    def test_builds_snapshot_and_prefers_established(self) -> None:
        resolver = names({1: "listener", 2: "browser"})
        connection_list = [
            FakeConnection(("127.0.0.1", 8080), 1, psutil.CONN_LISTEN),
            FakeConnection(("127.0.0.1", 8080), 2, psutil.CONN_ESTABLISHED),
        ]
        process_map = ProcessMap(name_resolver=resolver)
        self.assertEqual(process_map.update(connection_list), 1)
        info = process_map.lookup("127.0.0.1", 8080)
        self.assertEqual(info, ProcessInfo(2, "browser"))

        reverse = list(reversed(connection_list))
        process_map.update(reverse)
        self.assertEqual(
            process_map.lookup("127.0.0.1", 8080),
            ProcessInfo(2, "browser"),
        )

    def test_ipv6_lookup_uses_canonical_text(self) -> None:
        process_map = ProcessMap(name_resolver=names({7: "server"}))
        process_map.update([
            FakeConnection(("2001:0db8:0:0:0:0:0:1", 8443), 7),
        ])
        self.assertEqual(
            process_map.lookup("2001:db8::1", 8443),
            ProcessInfo(7, "server"),
        )
        self.assertIsNone(process_map.lookup("2001:db8::2", 8443))

    def test_skips_missing_or_malformed_rows(self) -> None:
        calls = []

        def resolver(pid):
            calls.append(pid)
            if pid == 9:
                raise RuntimeError("denied")
            return {1: "one"}.get(pid)

        process_map = ProcessMap(name_resolver=resolver)
        count = process_map.update([
            FakeConnection(None, 1),
            FakeConnection((), 1),
            FakeConnection(("1.2.3.4", "bad"), 1),
            FakeConnection(("1.2.3.4", 80), None),
            FakeConnection(("1.2.3.4", 80), 9),
            FakeConnection(("1.2.3.4", 81), 1),
            FakeConnection(("1.2.3.4", 82), 1),
        ])
        self.assertEqual(count, 2)
        self.assertEqual(process_map.lookup("1.2.3.4", 81).name, "one")
        self.assertEqual(process_map.lookup("1.2.3.4", 82).name, "one")
        self.assertEqual(calls.count(1), 1)  # names are cached per PID
        self.assertIn(9, calls)

    def test_update_survives_resolver_exception(self) -> None:
        process_map = ProcessMap(
            name_resolver=lambda _pid: (_ for _ in ()).throw(ValueError())
        )
        self.assertEqual(
            process_map.update([FakeConnection(("1.2.3.4", 80), 5)]),
            0,
        )
        self.assertIsNone(process_map.lookup("1.2.3.4", 80))

    def test_refresh_success_populates_timestamp(self) -> None:
        process_map = ProcessMap(name_resolver=names({3: "app"}))
        connection = FakeConnection(("10.0.0.5", 5000), 3)
        with patch(
            "app.services.process_map.psutil.net_connections",
            return_value=[connection],
        ):
            self.assertEqual(process_map.refresh(), 1)
        self.assertEqual(process_map.last_error, "")
        self.assertGreater(process_map.last_refresh_ts, 0)
        self.assertEqual(process_map.endpoint_count, 1)

    def test_refresh_access_denied_keeps_previous_snapshot(self) -> None:
        process_map = ProcessMap()
        previous = {("10.0.0.1", 80): ProcessInfo(1, "old")}
        process_map.set_snapshot(previous)
        with patch(
            "app.services.process_map.psutil.net_connections",
            side_effect=psutil.AccessDenied(pid=1),
        ):
            self.assertEqual(process_map.refresh(), 1)
        self.assertIn("无法读取系统 TCP 连接", process_map.last_error)
        self.assertEqual(process_map.snapshot, previous)

    def test_refresh_unexpected_error_keeps_previous_snapshot(self) -> None:
        process_map = ProcessMap()
        previous = {("10.0.0.1", 80): ProcessInfo(1, "old")}
        process_map.set_snapshot(previous)
        with patch(
            "app.services.process_map.psutil.net_connections",
            side_effect=RuntimeError("boom"),
        ):
            self.assertEqual(process_map.refresh(), 1)
        self.assertIn("读取 TCP 连接失败", process_map.last_error)
        self.assertEqual(process_map.snapshot, previous)

    def test_set_snapshot_replaces_and_clears_error(self) -> None:
        process_map = ProcessMap()
        process_map.last_error = "old error"
        mapping = {("10.0.0.1", 443): ProcessInfo(4, "edge")}
        process_map.set_snapshot(mapping)
        self.assertEqual(process_map.snapshot, mapping)
        self.assertEqual(process_map.last_error, "")
        self.assertEqual(process_map.endpoint_count, 1)


if __name__ == "__main__":
    unittest.main()
