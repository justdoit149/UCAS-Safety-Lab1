"""Capture worker thread.

The worker owns the libpcap handle, dissects frames off the UI thread, and
emits packets in small batches so the table does not repaint per frame.
"""

from __future__ import annotations

import threading
import time

from PySide6.QtCore import QThread, Signal

from app.core.dissector import dissect
from app.core.models import Packet
from app.core.pcap_driver import NpcapNotFoundError, PcapError, PcapHandle


class CaptureWorker(QThread):
    """Owns the live PcapHandle and emits packets/counters to the UI."""

    opened = Signal(str, int)          # device name, datalink type
    packets_ready = Signal(list)      # batch of app.core.models.Packet
    stats_ready = Signal(int, int, int, int)  # captured, received, dropped, if_dropped
    error = Signal(str)

    BATCH_SIZE = 128
    BATCH_INTERVAL = 0.1

    def __init__(
        self,
        device_name: str,
        snaplen: int = 262144,
        promisc: bool = True,
        parent=None,
    ):
        super().__init__(parent)
        self.device_name = device_name
        self.snaplen = snaplen
        self.promisc = promisc
        self.captured = 0
        self._stop_event = threading.Event()

    def stop(self) -> None:
        """Ask the capture loop to exit; safe to call from the UI thread."""
        self._stop_event.set()

    def _emit_stats(self, handle: PcapHandle) -> None:
        try:
            received, dropped, if_dropped = handle.stats()
        except PcapError:
            received = dropped = if_dropped = 0
        self.stats_ready.emit(self.captured, received, dropped, if_dropped)

    def run(self) -> None:
        handle = None
        batch: list[Packet] = []
        index = 0
        try:
            handle = PcapHandle.open_live(
                self.device_name,
                snaplen=self.snaplen,
                promisc=self.promisc,
                timeout_ms=50,
            )
            self.opened.emit(self.device_name, handle.datalink)

            last_stats = time.monotonic()
            last_flush = last_stats
            while not self._stop_event.is_set():
                item = handle.next_packet()
                if item is not None:
                    ts, caplen, orig_len, raw = item
                    index += 1
                    self.captured += 1
                    try:
                        packet = dissect(
                            index,
                            ts,
                            raw,
                            orig_len,
                            handle.datalink,
                        )
                    except Exception as exc:  # pragma: no cover - defensive
                        packet = Packet(
                            index=index,
                            ts=ts,
                            caplen=len(raw),
                            orig_len=max(orig_len, len(raw)),
                            raw=raw,
                            linktype=handle.datalink,
                            proto_label="解析错误",
                            summary=f"dissector error: {exc!r}",
                            truncated=True,
                        )
                    batch.append(packet)

                now = time.monotonic()
                if len(batch) >= self.BATCH_SIZE or (
                    batch and now - last_flush >= self.BATCH_INTERVAL
                ):
                    self.packets_ready.emit(batch)
                    batch = []
                    last_flush = now

                if now - last_stats >= 0.2:
                    self._emit_stats(handle)
                    last_stats = now
        except NpcapNotFoundError as exc:
            self.error.emit(str(exc))
        except PcapError as exc:
            self.error.emit(str(exc))
        except Exception as exc:  # pragma: no cover - defensive for driver edge cases
            self.error.emit(f"抓包线程异常: {exc!r}")
        finally:
            if batch:
                self.packets_ready.emit(batch)
            if handle is not None:
                try:
                    self._emit_stats(handle)
                except Exception:
                    pass
                handle.close()
            else:
                self.stats_ready.emit(self.captured, 0, 0, 0)
