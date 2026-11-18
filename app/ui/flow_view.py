"""Flow table, process filter and per-flow timeline."""

from __future__ import annotations

from PySide6.QtCore import QModelIndex, Qt, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSplitter,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.core.models import Flow, Packet
from app.ui.flow_model import (
    COL_APP,
    COL_BYTES,
    COL_DST,
    COL_DURATION,
    COL_LAST,
    COL_PACKETS,
    COL_PROCESS,
    COL_PROTO,
    COL_SRC,
    COL_STATE,
    FLOW_SORT_ROLE,
    FlowFilterProxyModel,
    FlowTableModel,
)


class FlowTimelineView(QWidget):
    packet_activated = Signal(int)

    MAX_ROWS = 1000

    def __init__(self, parent=None):
        super().__init__(parent)
        self._flow: Flow | None = None
        self._packet_count = -1

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(3)
        self.lbl_info = QLabel("选择一条流查看时序")
        self.lbl_info.setStyleSheet("color: #555;")
        root.addWidget(self.lbl_info)

        self.table = QTableWidget(0, 6, self)
        self.table.setHorizontalHeaderLabels(
            ["序号", "相对时间", "方向", "标志", "长度", "摘要"]
        )
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(21)
        header = self.table.horizontalHeader()
        header.setHighlightSections(False)
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setSectionResizeMode(5, QHeaderView.Stretch)
        self.table.setColumnWidth(0, 50)
        self.table.setColumnWidth(1, 78)
        self.table.setColumnWidth(2, 56)
        self.table.setColumnWidth(3, 100)
        self.table.setColumnWidth(4, 48)
        self.table.doubleClicked.connect(self._on_double_click)
        root.addWidget(self.table, 1)

    def set_flow(self, flow: Flow | None) -> None:
        if flow is None:
            self.clear_flow()
            return
        if flow is self._flow and flow.packet_count == self._packet_count:
            return
        self._flow = flow
        self._packet_count = flow.packet_count
        packets = flow.packets[: self.MAX_ROWS]
        self.table.setUpdatesEnabled(False)
        self.table.setRowCount(len(packets))
        for row, packet in enumerate(packets):
            self._fill_row(row, flow, packet)
        self.table.setUpdatesEnabled(True)
        if flow.packet_count > len(packets):
            self.lbl_info.setText(
                f"共 {flow.packet_count} 包，显示前 {len(packets)} 包"
            )
        else:
            self.lbl_info.setText(f"共 {flow.packet_count} 包")

    def clear_flow(self) -> None:
        self._flow = None
        self._packet_count = -1
        self.table.setRowCount(0)
        self.lbl_info.setText("选择一条流查看时序")

    def _fill_row(self, row: int, flow: Flow, packet: Packet) -> None:
        relative = max(0.0, packet.ts - flow.first_ts)
        direction = flow.direction_label(packet)
        values = [
            str(packet.index),
            f"+{relative:.6f}",
            direction,
            packet.tcp_flags or "-",
            str(packet.orig_len),
            packet.summary,
        ]
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setToolTip(packet.summary)
            if column in (0, 1, 4):
                item.setTextAlignment(int(Qt.AlignRight | Qt.AlignVCenter))
            if column == 0:
                item.setData(Qt.UserRole, packet.index)
            if column == 2:
                item.setForeground(
                    QBrush(QColor("#1565c0" if direction == "A → B" else "#2e7d32"))
                )
            self.table.setItem(row, column, item)

    def _on_double_click(self, index) -> None:
        item = self.table.item(index.row(), 0)
        if item is None:
            return
        packet_index = item.data(Qt.UserRole)
        if packet_index is not None:
            self.packet_activated.emit(int(packet_index))


class FlowView(QWidget):
    refresh_processes_requested = Signal()
    show_flow_packets_requested = Signal(object)
    packet_activated = Signal(int)
    process_column_toggled = Signal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._flows: list[Flow] = []
        self._process_options: list[tuple[int, str]] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(6, 4, 6, 4)
        root.setSpacing(4)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("按进程筛选 TCP:"))
        self.combo_process = QComboBox()
        self.combo_process.setMinimumWidth(210)
        self.combo_process.addItem("全部进程", None)
        controls.addWidget(self.combo_process)
        self.btn_refresh = QPushButton("刷新进程")
        self.btn_show = QPushButton("显示所选流数据包")
        self.btn_show.setEnabled(False)
        self.btn_clear = QPushButton("清除筛选")
        controls.addWidget(self.btn_refresh)
        controls.addWidget(self.btn_show)
        controls.addWidget(self.btn_clear)
        controls.addSpacing(8)
        self.chk_process_column = QCheckBox("包列表显示进程列")
        controls.addWidget(self.chk_process_column)
        controls.addStretch(1)
        self.lbl_flow_count = QLabel("流: 0 | TCP: 0")
        self.lbl_flow_count.setStyleSheet("color: #555;")
        controls.addWidget(self.lbl_flow_count)
        root.addLayout(controls)

        self.lbl_process_status = QLabel("进程映射: 未刷新")
        self.lbl_process_status.setStyleSheet("color: #777;")
        root.addWidget(self.lbl_process_status)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        self.flow_model = FlowTableModel(self)
        self.flow_proxy = FlowFilterProxyModel(self)
        self.flow_proxy.setSourceModel(self.flow_model)
        self.flow_proxy.setSortRole(FLOW_SORT_ROLE)
        self.flow_proxy.setDynamicSortFilter(True)
        self.flow_table = QTableView()
        self.flow_table.setModel(self.flow_proxy)
        self.flow_table.setSortingEnabled(True)
        self.flow_table.sortByColumn(COL_LAST, Qt.DescendingOrder)
        self.flow_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.flow_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.flow_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.flow_table.setAlternatingRowColors(True)
        self.flow_table.setShowGrid(False)
        self.flow_table.setWordWrap(False)
        self.flow_table.verticalHeader().setVisible(False)
        self.flow_table.verticalHeader().setDefaultSectionSize(21)
        header = self.flow_table.horizontalHeader()
        header.setHighlightSections(False)
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setSectionResizeMode(COL_PROCESS, QHeaderView.Stretch)
        for column, width in (
            (COL_PROTO, 44),
            (COL_SRC, 128),
            (COL_DST, 128),
            (COL_STATE, 84),
            (COL_PACKETS, 42),
            (COL_BYTES, 52),
            (COL_DURATION, 54),
            (COL_APP, 48),
            (COL_LAST, 80),
        ):
            self.flow_table.setColumnWidth(column, width)
        splitter.addWidget(self.flow_table)

        self.timeline = FlowTimelineView()
        splitter.addWidget(self.timeline)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([800, 440])
        root.addWidget(splitter, 1)

        self.combo_process.currentIndexChanged.connect(
            self._on_process_changed
        )
        self.btn_refresh.clicked.connect(self.refresh_processes_requested)
        self.btn_show.clicked.connect(self._show_selected)
        self.btn_clear.clicked.connect(self._clear_filter)
        self.chk_process_column.toggled.connect(
            self.process_column_toggled
        )
        self.flow_table.doubleClicked.connect(self._show_selected)
        self.flow_table.selectionModel().currentRowChanged.connect(
            self._on_flow_selected
        )
        self.timeline.packet_activated.connect(self.packet_activated)
        self.flow_proxy.set_process_filter(None, tcp_only=False)

    # --------------------------------------------------------------- data
    def set_flows(self, flows: list[Flow]) -> None:
        selected = self.selected_flow()
        selected_key = selected.key if selected is not None else None
        scroll = self.flow_table.verticalScrollBar().value()
        self._flows = list(flows)
        self.flow_model.set_flows(self._flows)
        self._refresh_process_options()
        self._update_count_label()
        if selected_key is not None and self.select_flow_key(selected_key):
            return
        self._clear_selection()
        self.flow_table.verticalScrollBar().setValue(
            min(scroll, self.flow_table.verticalScrollBar().maximum())
        )

    def update_processes(self) -> None:
        self.flow_model.update_processes()
        self._refresh_process_options()
        self._update_count_label()

    def clear(self) -> None:
        self._flows = []
        self.flow_model.set_flows([])
        self._process_options = []
        self.combo_process.blockSignals(True)
        self.combo_process.clear()
        self.combo_process.addItem("全部进程", None)
        self.combo_process.blockSignals(False)
        self.flow_proxy.set_process_filter(None, tcp_only=False)
        self._clear_selection()
        self._update_count_label()

    def selected_flow(self) -> Flow | None:
        index = self.flow_table.currentIndex()
        if not index.isValid():
            return None
        source = self.flow_proxy.mapToSource(index)
        return self.flow_model.flow_at(source.row())

    def select_flow_key(self, key) -> bool:
        for row, flow in enumerate(self._flows):
            if flow.key != key:
                continue
            source = self.flow_model.index(row, 0)
            proxy = self.flow_proxy.mapFromSource(source)
            if proxy.isValid():
                self.flow_table.selectRow(proxy.row())
                self.flow_table.scrollTo(proxy)
                return True
            return False
        return False

    def set_process_status(self, text: str, error: bool = False) -> None:
        self.lbl_process_status.setText(text)
        self.lbl_process_status.setStyleSheet(
            "color: #c62828;" if error else "color: #777;"
        )

    # ------------------------------------------------------------ internal
    def _on_flow_selected(self, current, previous) -> None:
        del previous
        if not current.isValid():
            self.timeline.clear_flow()
            self.btn_show.setEnabled(False)
            return
        flow = self.selected_flow()
        self.timeline.set_flow(flow)
        self.btn_show.setEnabled(flow is not None)

    def _show_selected(self, *_args) -> None:
        flow = self.selected_flow()
        if flow is not None:
            self.show_flow_packets_requested.emit(flow)

    def _clear_filter(self, *_args) -> None:
        self.combo_process.setCurrentIndex(0)
        self.flow_proxy.set_process_filter(None, tcp_only=False)
        self._clear_selection()
        self._update_count_label()

    def _on_process_changed(self, index: int) -> None:
        del index
        pid = self.combo_process.currentData()
        self.flow_proxy.set_process_filter(
            pid if pid is not None else None,
            tcp_only=pid is not None,
        )
        self._update_count_label()
        self._clear_selection()

    def _clear_selection(self) -> None:
        self.flow_table.clearSelection()
        self.flow_table.setCurrentIndex(QModelIndex())
        self.timeline.clear_flow()
        self.btn_show.setEnabled(False)

    def _update_count_label(self) -> None:
        total = len(self._flows)
        tcp = sum(1 for flow in self._flows if flow.protocol == "TCP")
        visible = self.flow_proxy.rowCount()
        if visible == total:
            self.lbl_flow_count.setText(f"流: {total} | TCP: {tcp}")
        else:
            self.lbl_flow_count.setText(
                f"流: {visible}/{total} | TCP: {tcp}"
            )

    def _refresh_process_options(self) -> None:
        options: dict[int, str] = {}
        for flow in self._flows:
            if flow.protocol != "TCP":
                continue
            for proc in flow.endpoint_procs:
                pid = int(getattr(proc, "pid", 0) or 0)
                if not pid:
                    continue
                name = str(
                    getattr(proc, "display", "")
                    or getattr(proc, "name", "")
                    or "?"
                )
                options[pid] = name
        items = sorted(options.items(), key=lambda item: (item[1].lower(), item[0]))
        if items == self._process_options:
            return

        current_pid = self.combo_process.currentData()
        self._process_options = items
        self.combo_process.blockSignals(True)
        self.combo_process.clear()
        self.combo_process.addItem("全部进程", None)
        for pid, name in items:
            self.combo_process.addItem(f"{name}", pid)
        target = 0
        for index in range(self.combo_process.count()):
            if self.combo_process.itemData(index) == current_pid:
                target = index
                break
        self.combo_process.setCurrentIndex(target)
        self.combo_process.blockSignals(False)
        if current_pid is not None and target == 0:
            self.flow_proxy.set_process_filter(None, tcp_only=False)
            self._update_count_label()
