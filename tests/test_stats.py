"""Tests for the statistics accumulator used by the chart tab."""

from __future__ import annotations

import unittest

from app.core.models import Packet
from app.services.stats import CaptureStats


def packet(ts: float, *, label: str = "TCP", transport: str = "TCP",
           orig_len: int = 100) -> Packet:
    return Packet(
        index=1,
        ts=ts,
        caplen=orig_len,
        orig_len=orig_len,
        raw=b"",
        linktype=1,
        transport=transport,
        proto_label=label,
    )


class CaptureStatsTests(unittest.TestCase):
    def test_empty_state(self) -> None:
        stats = CaptureStats()
        self.assertEqual(stats.total_packets, 0)
        self.assertEqual(stats.total_bytes, 0)
        self.assertEqual(stats.protocol_counts(), [])
        self.assertEqual(stats.rate_series(), ([], []))
        self.assertEqual(stats.current_rate, 0)
        self.assertEqual(stats.elapsed_seconds, 0.0)
        stats.add_packets([])
        self.assertEqual(stats.total_packets, 0)

    def test_counts_bytes_and_order(self) -> None:
        stats = CaptureStats()
        stats.add_packets([
            packet(10.0, label="TCP", orig_len=60),
            packet(10.2, label="HTTP", orig_len=500),
            packet(10.4, label="TCP", orig_len=40),
            packet(10.6, label="DNS", orig_len=80),
            packet(10.8, label="TCP", orig_len=100),
        ])
        self.assertEqual(stats.total_packets, 5)
        self.assertEqual(stats.total_bytes, 780)
        self.assertEqual(
            stats.protocol_counts(),
            [("TCP", 3), ("DNS", 1), ("HTTP", 1)],
        )

    def test_rate_uses_packet_timestamps(self) -> None:
        stats = CaptureStats()
        stats.add_packets([
            packet(100.1), packet(100.2), packet(100.9),
            packet(101.0), packet(102.5),
        ])
        self.assertEqual(stats.current_rate, 1)  # bucket 102
        xs, ys = stats.rate_series()
        self.assertEqual(len(xs), 60)
        self.assertEqual(xs[-1], 59.0)
        self.assertEqual(ys[-1], 1)
        self.assertEqual(ys[-3], 3)  # bucket 100
        self.assertEqual(ys[-2], 1)  # bucket 101
        self.assertAlmostEqual(stats.elapsed_seconds, 2.4, places=6)

    def test_window_trims_old_buckets(self) -> None:
        stats = CaptureStats(rate_window_seconds=3)
        stats.add_packets([packet(10.0), packet(11.0), packet(12.0)])
        stats.add_packets([packet(20.0)])
        xs, ys = stats.rate_series()
        self.assertEqual(xs, [0.0, 1.0, 2.0])
        self.assertEqual(ys, [0, 0, 1])
        self.assertEqual(stats.current_rate, 1)

    def test_label_fallback(self) -> None:
        stats = CaptureStats()
        stats.add_packets([
            packet(1.0, label="", transport="UDP"),
            packet(1.1, label="", transport=""),
        ])
        self.assertEqual(
            stats.protocol_counts(),
            [("Other", 1), ("UDP", 1)],
        )

    def test_reset(self) -> None:
        stats = CaptureStats()
        stats.add_packets([packet(1.0)])
        stats.reset()
        self.assertEqual(stats.total_packets, 0)
        self.assertEqual(stats.total_bytes, 0)
        self.assertEqual(stats.protocol_counts(), [])
        self.assertEqual(stats.rate_series(), ([], []))

    def test_negative_length_is_clamped(self) -> None:
        stats = CaptureStats()
        stats.add_packets([packet(1.0, orig_len=-5)])
        self.assertEqual(stats.total_bytes, 0)


if __name__ == "__main__":
    unittest.main()
