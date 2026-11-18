"""Capture worker thread.

M1 only counts raw frames.  Dissection is added in M2, so no packet
objects are created here yet.
"""

from __future__ import annotations

import threading
import time

from PySide6.QtCore import QThread, Signal

from app.core.pcap_driver import NpcapNotFoundError, PcapError, PcapHandle


class CaptureWorker(QThread):
    """Owns the live PcapHandle and emits periodic counters to the UI."""

    opened = Signal(str, int)          # device name, datalink type
    stats_ready = Signal(int, int, int, int)  # captured, received, dropped, if_dropped
    error = Signal(str)

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
        try:
            handle = PcapHandle.open_live(
                self.device_name,
                snaplen=self.snaplen,
                promisc=self.promisc,
                timeout_ms=50,
            )
            self.opened.emit(self.device_name, handle.datalink)

            last_emit = time.monotonic()
            while not self._stop_event.is_set():
                item = handle.next_packet()
                if item is not None:
                    self.captured += 1

                now = time.monotonic()
                if now - last_emit >= 0.2:
                    self._emit_stats(handle)
                    last_emit = now
        except NpcapNotFoundError as exc:
            self.error.emit(str(exc))
        except PcapError as exc:
            self.error.emit(str(exc))
        except Exception as exc:  # pragma: no cover - defensive for driver edge cases
            self.error.emit(f"抓包线程异常: {exc!r}")
        finally:
            if handle is not None:
                try:
                    self._emit_stats(handle)
                except Exception:
                    pass
                handle.close()
            else:
                self.stats_ready.emit(self.captured, 0, 0, 0)
