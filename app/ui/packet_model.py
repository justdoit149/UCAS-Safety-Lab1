"""Qt table model for dissected packets."""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
    Qt,
)
from PySide6.QtGui import QBrush, QColor

from app.core.models import Packet

COL_NO = 0
COL_TIME = 1
COL_SRC = 2
COL_DST = 3
COL_PROTO = 4
COL_LENGTH = 5
COL_INFO = 6
COL_PROCESS = 7

HEADERS = ["序号", "时间", "源地址", "目的地址", "协议", "长度", "信息", "进程"]
SORT_ROLE = Qt.UserRole + 1

_PROTOCOL_COLORS = {
    "TCP": "#1565c0",
    "UDP": "#2e7d32",
    "ICMP": "#ef6c00",
    "ICMPv6": "#ef6c00",
    "ARP": "#6a1b9a",
    "IPv4": "#455a64",
    "IPv6": "#455a64",
    "HTTP": "#00695c",
    "DNS": "#ad1457",
    "TLS": "#5e35b1",
}


class PacketTableModel(QAbstractTableModel):
    """Holds Packet objects and exposes the seven Wireshark-style columns."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._packets: list[Packet] = []
        self._process_map = None

    # ------------------------------------------------------------ Qt model
    def rowCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._packets)

    def columnCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):  # noqa: N802
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return HEADERS[section] if 0 <= section < len(HEADERS) else None
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self._packets)):
            return None
        packet = self._packets[index.row()]
        column = index.column()

        if role == Qt.DisplayRole:
            if column == COL_NO:
                return str(packet.index)
            if column == COL_TIME:
                return _format_time(packet.ts)
            if column == COL_SRC:
                return packet.display_src
            if column == COL_DST:
                return packet.display_dst
            if column == COL_PROTO:
                return packet.proto_label
            if column == COL_LENGTH:
                return str(packet.orig_len)
            if column == COL_INFO:
                return packet.summary
            if column == COL_PROCESS:
                process = self._lookup_process(packet)
                return process.display if process is not None else "-"
            return None

        if role == Qt.ToolTipRole:
            if column == COL_INFO:
                return packet.summary
            return (
                f"#{packet.index}  {packet.proto_label}\n"
                f"{packet.display_src} → {packet.display_dst}\n"
                f"caplen={packet.caplen}, len={packet.orig_len}"
            )

        if role == Qt.TextAlignmentRole:
            if column in (COL_NO, COL_TIME, COL_LENGTH):
                return int(Qt.AlignRight | Qt.AlignVCenter)
            return int(Qt.AlignLeft | Qt.AlignVCenter)

        if role == Qt.ForegroundRole and column == COL_PROTO:
            color = _PROTOCOL_COLORS.get(packet.proto_label)
            if color:
                return QBrush(QColor(color))
            return None

        if role == SORT_ROLE:
            if column == COL_NO:
                return packet.index
            if column == COL_TIME:
                return packet.ts
            if column == COL_SRC:
                return packet.display_src.lower()
            if column == COL_DST:
                return packet.display_dst.lower()
            if column == COL_PROTO:
                return packet.proto_label.lower()
            if column == COL_LENGTH:
                return packet.orig_len
            if column == COL_INFO:
                return packet.summary.lower()
            if column == COL_PROCESS:
                process = self._lookup_process(packet)
                return process.name.lower() if process is not None else ""
            return None

        return None

    def flags(self, index: QModelIndex):
        if not index.isValid():
            return Qt.NoItemFlags
        return Qt.ItemIsEnabled | Qt.ItemIsSelectable

    # --------------------------------------------------------------- data
    def append_packets(self, packets: list[Packet]) -> None:
        if not packets:
            return
        first = len(self._packets)
        last = first + len(packets) - 1
        self.beginInsertRows(QModelIndex(), first, last)
        self._packets.extend(packets)
        self.endInsertRows()

    def clear(self) -> None:
        if not self._packets:
            return
        self.beginResetModel()
        self._packets.clear()
        self.endResetModel()

    def set_process_map(self, process_map) -> None:
        self._process_map = process_map
        self.refresh_process_column()

    def refresh_process_column(self) -> None:
        if self._packets:
            # Do not include SORT_ROLE here: a 3 s mapping refresh must not
            # force the proxy to re-sort up to 200k rows while the user is
            # capturing.  A later header click re-sorts with fresh labels.
            self.dataChanged.emit(
                self.index(0, COL_PROCESS),
                self.index(len(self._packets) - 1, COL_PROCESS),
                [Qt.DisplayRole, Qt.ToolTipRole],
            )

    def _lookup_process(self, packet: Packet):
        if self._process_map is None:
            return None
        # A response packet's source is the remote server; fall back to the
        # destination so the column shows the local process in both directions.
        for ip, port in (
            (packet.ip_src, packet.sport),
            (packet.ip_dst, packet.dport),
        ):
            if not ip:
                continue
            try:
                process = self._process_map.lookup(ip, port)
            except Exception:
                process = None
            if process is not None:
                return process
        return None

    def packet_at(self, row: int) -> Packet | None:
        if 0 <= row < len(self._packets):
            return self._packets[row]
        return None

    @property
    def packets(self) -> list[Packet]:
        return list(self._packets)


class PacketFilterProxyModel(QSortFilterProxyModel):
    """Sort/filter proxy that evaluates a compiled display-filter predicate."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._predicate = None

    def set_packet_filter(self, predicate) -> None:
        self._predicate = predicate
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent) -> bool:  # noqa: N802
        if self._predicate is None:
            return True
        model = self.sourceModel()
        if not isinstance(model, PacketTableModel):
            return True
        packet = model.packet_at(source_row)
        if packet is None:
            return False
        try:
            return bool(self._predicate(packet))
        except Exception:
            return False


def _format_time(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]
    except (OverflowError, OSError, ValueError):
        return "-"
