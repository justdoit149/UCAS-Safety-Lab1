"""Qt models for the bidirectional flow table."""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
    Qt,
)
from PySide6.QtGui import QBrush, QColor

from app.core.flowkey import endpoint_text
from app.core.models import Flow

COL_PROTO = 0
COL_SRC = 1
COL_DST = 2
COL_STATE = 3
COL_PACKETS = 4
COL_BYTES = 5
COL_DURATION = 6
COL_APP = 7
COL_PROCESS = 8
COL_LAST = 9

HEADERS = [
    "协议",
    "源",
    "目的",
    "状态",
    "包数",
    "字节",
    "时长",
    "应用",
    "进程",
    "最后活动",
]
FLOW_SORT_ROLE = Qt.UserRole + 1

_STATE_COLORS = {
    "ESTABLISHED": "#2e7d32",
    "SYN_SENT": "#1565c0",
    "SYN_RCVD": "#1565c0",
    "FIN_WAIT": "#ef6c00",
    "CLOSED": "#616161",
    "EXPIRED": "#9e9e9e",
    "NEW": "#455a64",
    "ACTIVE": "#2e7d32",
}


class FlowTableModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._flows: list[Flow] = []

    def rowCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._flows)

    def columnCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):  # noqa: N802
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return HEADERS[section] if 0 <= section < len(HEADERS) else None
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self._flows)):
            return None
        flow = self._flows[index.row()]
        column = index.column()

        if role == Qt.DisplayRole:
            if column == COL_PROTO:
                return flow.protocol
            if column == COL_SRC:
                return endpoint_text(flow.src_ip, flow.src_port)
            if column == COL_DST:
                return endpoint_text(flow.dst_ip, flow.dst_port)
            if column == COL_STATE:
                return flow.state
            if column == COL_PACKETS:
                return str(flow.packet_count)
            if column == COL_BYTES:
                return str(flow.byte_count)
            if column == COL_DURATION:
                return f"{flow.duration:.3f}s"
            if column == COL_APP:
                return flow.app or flow.protocol
            if column == COL_PROCESS:
                return flow.process_label
            if column == COL_LAST:
                return _format_time(flow.last_ts)
            return None

        if role == Qt.ToolTipRole:
            return (
                f"{flow.protocol}  {endpoint_text(flow.src_ip, flow.src_port)}"
                f" ↔ {endpoint_text(flow.dst_ip, flow.dst_port)}\n"
                f"状态: {flow.state} | 包数: {flow.packet_count} | "
                f"字节: {flow.byte_count} | 应用: {flow.app or '-'}\n"
                f"进程: {flow.process_label}\n"
                f"首包: {_format_time(flow.first_ts)} | "
                f"末包: {_format_time(flow.last_ts)}"
            )

        if role == Qt.TextAlignmentRole:
            if column in (COL_PACKETS, COL_BYTES, COL_DURATION, COL_LAST):
                return int(Qt.AlignRight | Qt.AlignVCenter)
            return int(Qt.AlignLeft | Qt.AlignVCenter)

        if role == Qt.ForegroundRole and column == COL_STATE:
            color = _STATE_COLORS.get(flow.state)
            if color:
                return QBrush(QColor(color))
            return None

        if role == FLOW_SORT_ROLE:
            if column == COL_PROTO:
                return flow.protocol.lower()
            if column == COL_SRC:
                return endpoint_text(flow.src_ip, flow.src_port).lower()
            if column == COL_DST:
                return endpoint_text(flow.dst_ip, flow.dst_port).lower()
            if column == COL_STATE:
                return flow.state.lower()
            if column == COL_PACKETS:
                return flow.packet_count
            if column == COL_BYTES:
                return flow.byte_count
            if column == COL_DURATION:
                return flow.duration
            if column == COL_APP:
                return (flow.app or flow.protocol).lower()
            if column == COL_PROCESS:
                return flow.process_label.lower()
            if column == COL_LAST:
                return flow.last_ts
            return None

        return None

    def flags(self, index: QModelIndex):
        if not index.isValid():
            return Qt.NoItemFlags
        return Qt.ItemIsEnabled | Qt.ItemIsSelectable

    def set_flows(self, flows: list[Flow]) -> None:
        self.beginResetModel()
        self._flows = list(flows)
        self.endResetModel()

    def update_processes(self) -> None:
        if self._flows:
            self.dataChanged.emit(
                self.index(0, COL_PROCESS),
                self.index(len(self._flows) - 1, COL_PROCESS),
                [Qt.DisplayRole, Qt.ToolTipRole, FLOW_SORT_ROLE],
            )

    def flow_at(self, row: int) -> Flow | None:
        if 0 <= row < len(self._flows):
            return self._flows[row]
        return None

    @property
    def flows(self) -> list[Flow]:
        return list(self._flows)


class FlowFilterProxyModel(QSortFilterProxyModel):
    """Filter flows by local process, optionally restricting to TCP."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._pid: int | None = None
        self._tcp_only = False

    def set_process_filter(self, pid: int | None, tcp_only: bool = True) -> None:
        self._pid = None if pid is None else int(pid)
        self._tcp_only = bool(tcp_only)
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent) -> bool:  # noqa: N802
        model = self.sourceModel()
        if not isinstance(model, FlowTableModel):
            return True
        flow = model.flow_at(source_row)
        if flow is None:
            return False
        if self._tcp_only and flow.protocol != "TCP":
            return False
        if self._pid is None:
            return True
        return self._pid in flow.process_pids


def _format_time(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]
    except (OverflowError, OSError, ValueError):
        return "-"
