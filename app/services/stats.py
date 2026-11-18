"""Incremental packet statistics for the statistics tab."""

from __future__ import annotations

from collections import Counter

from app.core.models import Packet


class CaptureStats:
    """Accumulate protocol counts, bytes and a short packet-rate history.

    The accumulator is intentionally independent from Qt so it can be tested
    without a QApplication.  Rates are bucketed by the packet timestamp, which
    makes live and offline captures behave the same way.
    """

    def __init__(self, rate_window_seconds: int = 60) -> None:
        self.rate_window_seconds = max(2, int(rate_window_seconds))
        self.reset()

    def reset(self) -> None:
        self.total_packets = 0
        self.total_bytes = 0
        self.protocols: Counter[str] = Counter()
        self._rate: dict[int, int] = {}
        self._latest_ts: float | None = None
        self._first_ts: float | None = None

    def add_packets(self, packets: list[Packet]) -> None:
        if not packets:
            return
        for packet in packets:
            self.total_packets += 1
            self.total_bytes += max(0, int(packet.orig_len))
            label = packet.proto_label or packet.transport or "Other"
            self.protocols[label] += 1
            bucket = int(packet.ts)
            self._rate[bucket] = self._rate.get(bucket, 0) + 1
            self._latest_ts = max(self._latest_ts, packet.ts) \
                if self._latest_ts is not None else packet.ts
            self._first_ts = min(self._first_ts, packet.ts) \
                if self._first_ts is not None else packet.ts
        self._trim()

    def _trim(self) -> None:
        if self._latest_ts is None:
            return
        cutoff = int(self._latest_ts) - self.rate_window_seconds + 1
        for bucket in [key for key in self._rate if key < cutoff]:
            del self._rate[bucket]

    def protocol_counts(self) -> list[tuple[str, int]]:
        return sorted(self.protocols.items(), key=lambda item: (-item[1], item[0]))

    def rate_series(self) -> tuple[list[float], list[int]]:
        """Return (relative seconds, packets per second) for the rate plot."""
        if not self._rate:
            return [], []
        latest = max(self._rate)
        start = latest - self.rate_window_seconds + 1
        buckets = range(start, latest + 1)
        xs = [float(bucket - start) for bucket in buckets]
        ys = [self._rate.get(bucket, 0) for bucket in buckets]
        return xs, ys

    @property
    def current_rate(self) -> int:
        if not self._rate:
            return 0
        return self._rate.get(max(self._rate), 0)

    @property
    def elapsed_seconds(self) -> float:
        if self._first_ts is None or self._latest_ts is None:
            return 0.0
        return max(0.0, self._latest_ts - self._first_ts)
