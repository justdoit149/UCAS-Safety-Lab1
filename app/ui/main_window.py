"""Main window: packet list, protocol detail tree, hex dump and statistics."""

from __future__ import annotations

import os
from datetime import datetime

from PySide6.QtCore import QModelIndex, Qt, QTimer
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from app.core.app_protocols import ApplicationContext
from app.core.dissector import dissect
from app.core.flowkey import endpoint_text
from app.core.models import Packet
from app.core.filtering import (
    CAPTURE_FILTER_PRESETS,
    DISPLAY_FILTER_PRESETS,
    CaptureFilterHint,
    FilterSyntaxError,
    compile_display_filter,
    resolve_capture_filter,
)
from app.core.pcap_driver import (
    NpcapNotFoundError,
    PcapError,
    libpcap_version,
    list_devices,
)
from app.core.pcap_io import (
    PcapFormatError,
    PcapWriteError,
    read_pcap,
    write_pcap,
)
from app.services.capture import CaptureWorker
from app.services.flows import FlowManager
from app.services.process_map import ProcessMap
from app.services.stats import CaptureStats
from app.ui.detail_view import DetailView
from app.ui.flow_view import FlowView
from app.ui.hex_view import HexView
from app.ui.packet_model import (
    COL_INFO,
    COL_NO,
    COL_PROCESS,
    COL_TIME,
    PacketFilterProxyModel,
    PacketTableModel,
    SORT_ROLE,
)
from app.ui.stats_view import StatsView

_BASE_TITLE = "1A 网络嗅探器 - M6 流跟踪与进程映射"

_DATALINK_NAMES = {
    0: "DLT_NULL（回环）",
    1: "DLT_EN10MB（以太网）",
    12: "DLT_RAW（裸 IP）",
}


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(_BASE_TITLE)
        self.resize(1280, 900)

        self._worker: CaptureWorker | None = None
        self._capture_available = False
        self._offline_path: str | None = None
        self.captured_count = 0
        self._active_capture_filter = ""
        self.max_packets = 200_000
        self._limit_warned = False
        self.stats = CaptureStats()
        self.flow_manager = FlowManager()
        self.process_map = ProcessMap()
        self._flow_dirty = False

        self._flow_timer = QTimer(self)
        self._flow_timer.setSingleShot(True)
        self._flow_timer.setInterval(250)
        self._flow_timer.timeout.connect(self._refresh_flow_table)
        self._process_timer = QTimer(self)
        self._process_timer.setInterval(3000)
        self._process_timer.timeout.connect(self._refresh_process_map)

        self._build_ui()
        self._load_devices()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        central = QWidget(self)
        root = QVBoxLayout(central)
        root.setContentsMargins(12, 12, 12, 8)
        root.setSpacing(8)

        control_row = QHBoxLayout()
        control_row.addWidget(QLabel("网卡:"))
        self.combo_devices = QComboBox()
        self.combo_devices.setMinimumWidth(360)
        control_row.addWidget(self.combo_devices, 1)
        self.btn_refresh = QPushButton("刷新网卡")
        self.btn_start = QPushButton("开始抓包")
        self.btn_stop = QPushButton("停止抓包")
        self.btn_stop.setEnabled(False)
        self.btn_clear = QPushButton("清空列表")
        self.btn_clear.setEnabled(False)
        control_row.addWidget(self.btn_refresh)
        control_row.addWidget(self.btn_start)
        control_row.addWidget(self.btn_stop)
        control_row.addWidget(self.btn_clear)
        root.addLayout(control_row)

        file_row = QHBoxLayout()
        self.btn_open = QPushButton("打开 pcap")
        self.btn_save_all = QPushButton("保存全部")
        self.btn_save_visible = QPushButton("保存显示结果")
        self.btn_save_all.setEnabled(False)
        self.btn_save_visible.setEnabled(False)
        self.lbl_file = QLabel("当前来源: 实时抓包")
        self.lbl_file.setStyleSheet("color: #555;")
        file_row.addWidget(self.btn_open)
        file_row.addWidget(self.btn_save_all)
        file_row.addWidget(self.btn_save_visible)
        file_row.addSpacing(12)
        file_row.addWidget(self.lbl_file, 1)
        root.addLayout(file_row)

        capture_filter_row = QHBoxLayout()
        capture_filter_row.addWidget(QLabel("抓包过滤(BPF):"))
        self.combo_capture_filter = QComboBox()
        self.combo_capture_filter.setEditable(True)
        self.combo_capture_filter.setInsertPolicy(QComboBox.NoInsert)
        self.combo_capture_filter.setMinimumWidth(420)
        self.combo_capture_filter.addItems(CAPTURE_FILTER_PRESETS)
        self.combo_capture_filter.setCurrentIndex(0)
        self.combo_capture_filter.setToolTip(
            "内核 BPF 过滤，开始抓包前生效；留空或选择“（不过滤）”表示全部。\n"
            "HTTP/HTTPS/DNS 会先翻译成对应的 BPF 端口表达式。"
        )
        capture_filter_row.addWidget(self.combo_capture_filter, 1)
        capture_hint = QLabel(
            "内核过滤，开始抓包前生效；HTTP/HTTPS/DNS 自动翻译为 BPF"
        )
        capture_hint.setStyleSheet("color: #777;")
        capture_filter_row.addWidget(capture_hint)
        root.addLayout(capture_filter_row)

        display_filter_row = QHBoxLayout()
        display_filter_row.addWidget(QLabel("显示过滤:"))
        self.edit_display_filter = QLineEdit()
        self.edit_display_filter.setPlaceholderText(
            "如 tcp and port 80；留空显示全部；支持 and/or/not 和括号"
        )
        self.edit_display_filter.setClearButtonEnabled(True)
        display_filter_row.addWidget(self.edit_display_filter, 1)
        self.combo_display_presets = QComboBox()
        self.combo_display_presets.addItem("常用表达式…")
        self.combo_display_presets.addItems(DISPLAY_FILTER_PRESETS)
        display_filter_row.addWidget(self.combo_display_presets)
        self.btn_apply_filter = QPushButton("应用")
        self.btn_clear_filter = QPushButton("清除")
        display_filter_row.addWidget(self.btn_apply_filter)
        display_filter_row.addWidget(self.btn_clear_filter)
        root.addLayout(display_filter_row)

        self.lbl_filter_error = QLabel("")
        self.lbl_filter_error.setStyleSheet("color: #c62828;")
        self.lbl_filter_error.setVisible(False)
        root.addWidget(self.lbl_filter_error)

        self._splitters = QSplitter(Qt.Vertical)
        self._splitters.setChildrenCollapsible(False)

        self.table = QTableView()
        self.model = PacketTableModel(self)
        self.proxy = PacketFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setSortRole(SORT_ROLE)
        self.proxy.setDynamicSortFilter(True)
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(COL_NO, Qt.AscendingOrder)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(22)
        header = self.table.horizontalHeader()
        header.setHighlightSections(False)
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setSectionResizeMode(COL_INFO, QHeaderView.Stretch)
        self.table.setColumnWidth(COL_NO, 64)
        self.table.setColumnWidth(COL_TIME, 112)
        self.table.setColumnWidth(2, 170)  # source
        self.table.setColumnWidth(3, 170)  # destination
        self.table.setColumnWidth(4, 78)   # protocol
        self.table.setColumnWidth(5, 64)   # length
        self.table.setColumnWidth(COL_PROCESS, 170)
        self.table.setColumnHidden(COL_PROCESS, True)
        self._splitters.addWidget(self.table)

        bottom = QSplitter(Qt.Horizontal)
        bottom.setChildrenCollapsible(False)
        self.detail = DetailView(bottom)
        self.hex_view = HexView(bottom)
        bottom.addWidget(self.detail)
        bottom.addWidget(self.hex_view)
        bottom.setStretchFactor(0, 2)
        bottom.setStretchFactor(1, 3)
        bottom.setSizes([460, 760])
        self._splitters.addWidget(bottom)
        self._splitters.setStretchFactor(0, 4)
        self._splitters.setStretchFactor(1, 3)
        self._splitters.setSizes([540, 260])
        root.addWidget(self._splitters, 1)

        self.bottom_tabs = QTabWidget()
        count_tab = QWidget()
        stats_row = QHBoxLayout(count_tab)
        stats_row.setContentsMargins(10, 6, 10, 6)
        self.lbl_captured = QLabel("0")
        self.lbl_received = QLabel("0")
        self.lbl_dropped = QLabel("0")
        self.lbl_ifdropped = QLabel("0")
        self.lbl_rows = QLabel("0")
        self.lbl_visible = QLabel("0")
        for caption, label in (
            ("已捕获帧:", self.lbl_captured),
            ("列表包数:", self.lbl_rows),
            ("显示包数:", self.lbl_visible),
            ("驱动接收:", self.lbl_received),
            ("驱动丢弃:", self.lbl_dropped),
            ("网卡丢弃:", self.lbl_ifdropped),
        ):
            stats_row.addWidget(QLabel(caption))
            stats_row.addWidget(label)
            stats_row.addSpacing(18)
        stats_row.addStretch(1)
        self.lbl_limit_notice = QLabel("")
        self.lbl_limit_notice.setStyleSheet("color: #b26a00;")
        self.lbl_limit_notice.setVisible(False)
        stats_row.addWidget(self.lbl_limit_notice)
        self.bottom_tabs.addTab(count_tab, "计数")

        self.stats_view = StatsView()
        self.bottom_tabs.addTab(self.stats_view, "统计图表")
        self.flow_view = FlowView()
        self.bottom_tabs.addTab(self.flow_view, "流表")
        self.bottom_tabs.setMaximumHeight(300)
        root.addWidget(self.bottom_tabs)

        self.model.set_process_map(self.process_map)
        self.setCentralWidget(central)
        self.statusBar().showMessage("正在检测 Npcap...")

        self.btn_refresh.clicked.connect(self._load_devices)
        self.btn_start.clicked.connect(self.start_capture)
        self.btn_stop.clicked.connect(self.stop_capture)
        self.btn_clear.clicked.connect(self.clear_packets)
        self.btn_open.clicked.connect(self.open_pcap_dialog)
        self.btn_save_all.clicked.connect(self.save_all_packets)
        self.btn_save_visible.clicked.connect(self.save_displayed_packets)
        self.btn_apply_filter.clicked.connect(self.apply_display_filter)
        self.btn_clear_filter.clicked.connect(self.clear_display_filter)
        self.edit_display_filter.returnPressed.connect(self.apply_display_filter)
        self.edit_display_filter.textChanged.connect(self._on_filter_text_changed)
        self.combo_display_presets.activated.connect(self._on_display_preset)
        self.detail.field_selected.connect(self.hex_view.highlight)
        self.table.selectionModel().currentRowChanged.connect(
            self._on_current_row_changed
        )
        self.flow_view.refresh_processes_requested.connect(
            self._refresh_process_map
        )
        self.flow_view.show_flow_packets_requested.connect(
            self._show_flow_packets
        )
        self.flow_view.packet_activated.connect(self._jump_to_packet)
        self.flow_view.process_column_toggled.connect(
            self._on_process_column_toggled
        )
        self.bottom_tabs.currentChanged.connect(self._on_bottom_tab_changed)

    # ------------------------------------------------------------- devices
    @staticmethod
    def _default_device_index(devices) -> int:
        """Prefer a physical Wi-Fi/Ethernet NIC; skip loopback and virtual/aux."""
        candidates = [
            (index, device)
            for index, device in enumerate(devices)
            if device.is_up
            and not device.is_loopback
            and not device.is_virtual
            and not device.is_auxiliary
        ]
        if candidates:
            def score(item) -> int:
                description = item[1].description.lower()
                if "wi-fi" in description or "wireless" in description:
                    return 0
                if "ethernet" in description:
                    return 1
                return 2

            return min(candidates, key=score)[0]

        loopback = next(
            (i for i, device in enumerate(devices) if device.is_loopback),
            None,
        )
        return loopback if loopback is not None else 0

    def _load_devices(self) -> None:
        self.combo_devices.clear()
        try:
            devices = list_devices()
            version = libpcap_version()
        except NpcapNotFoundError as exc:
            self._capture_available = False
            self._set_capturing(False)
            self.statusBar().showMessage("Npcap 不可用")
            QMessageBox.critical(self, "Npcap 未安装或不可用", str(exc))
            return
        except PcapError as exc:
            self._capture_available = False
            self._set_capturing(False)
            self.statusBar().showMessage("网卡枚举失败")
            QMessageBox.critical(self, "网卡枚举失败", str(exc))
            return

        self._capture_available = True
        for device in devices:
            self.combo_devices.addItem(device.display_name, device.name)
            index = self.combo_devices.count() - 1
            tooltip = device.name
            if device.description:
                tooltip = f"{device.description}\n{device.name}"
            self.combo_devices.setItemData(index, tooltip, Qt.ToolTipRole)

        if devices:
            self.combo_devices.setCurrentIndex(self._default_device_index(devices))

        self._set_capturing(self._worker is not None)
        if devices:
            self.statusBar().showMessage(
                f"{version} | 发现 {len(devices)} 块网卡 | 当前: "
                f"{self.combo_devices.currentText()}"
            )
        else:
            self.statusBar().showMessage(f"{version} | 未发现可用网卡")

    # ------------------------------------------------------------- capture
    def start_capture(self) -> None:
        if self._worker is not None or self._offline_path is not None:
            return
        device_name = self.combo_devices.currentData()
        if not device_name:
            QMessageBox.warning(self, "没有网卡", "请先选择一块网卡。")
            return

        try:
            bpf = resolve_capture_filter(self.combo_capture_filter.currentText())
        except CaptureFilterHint as exc:
            QMessageBox.warning(self, "抓包过滤只接受 BPF", str(exc))
            return

        self._active_capture_filter = bpf
        self.clear_packets()
        self.captured_count = 0
        self._update_counters(0, 0, 0, 0)

        self._worker = CaptureWorker(
            device_name,
            capture_filter=bpf,
            parent=self,
        )
        self._worker.opened.connect(self._on_opened)
        self._worker.packets_ready.connect(self._on_packets_ready)
        self._worker.stats_ready.connect(self._on_stats)
        self._worker.error.connect(self._on_error)
        self._worker.finished.connect(self._on_worker_finished)

        self._set_capturing(True)
        filter_note = f" | BPF: {bpf}" if bpf else ""
        self.statusBar().showMessage(f"正在打开网卡: {device_name}{filter_note}")
        self._worker.start()

    def stop_capture(self) -> None:
        if self._worker is None:
            return
        self.btn_stop.setEnabled(False)
        self.statusBar().showMessage("正在停止抓包...")
        self._worker.stop()

    def clear_packets(self) -> None:
        self.model.clear()
        self.detail.clear_packet()
        self.hex_view.set_packet(None)
        self.lbl_rows.setText("0")
        self.lbl_visible.setText("0")
        self.btn_clear.setEnabled(False)
        self.stats.reset()
        self.stats_view.update_stats(self.stats)
        self.flow_manager.clear()
        self.flow_view.clear()
        self._flow_dirty = False
        self._flow_timer.stop()
        self._limit_warned = False
        self.lbl_limit_notice.clear()
        self.lbl_limit_notice.setVisible(False)
        self._offline_path = None
        self.lbl_file.setText("当前来源: 实时抓包")
        self.setWindowTitle(_BASE_TITLE)
        self._update_file_buttons()
        self._set_capturing(self._worker is not None)

    # -------------------------------------------------------------- pcap IO
    def open_pcap_dialog(self) -> None:
        if self._worker is not None:
            return
        path, _selected = QFileDialog.getOpenFileName(
            self,
            "打开 pcap 文件",
            "",
            "pcap 文件 (*.pcap *.cap);;所有文件 (*)",
        )
        if path:
            self.open_pcap(path)

    def open_pcap(self, path: str) -> None:
        """Load a classic pcap file and run the same dissector as live capture."""
        if self._worker is not None:
            return
        try:
            offline = read_pcap(path, max_records=self.max_packets)
        except PcapFormatError as exc:
            QMessageBox.critical(self, "打开 pcap 失败", str(exc))
            return

        self.clear_packets()
        context = ApplicationContext()
        packets: list[Packet] = []
        for index, record in enumerate(offline.records, start=1):
            try:
                packet = dissect(
                    index,
                    record.ts,
                    record.raw,
                    record.orig_len,
                    offline.linktype,
                    context,
                )
            except Exception as exc:  # pragma: no cover - defensive
                packet = Packet(
                    index=index,
                    ts=record.ts,
                    caplen=record.caplen,
                    orig_len=record.orig_len,
                    raw=record.raw,
                    linktype=offline.linktype,
                    proto_label="解析错误",
                    summary=f"dissector error: {exc!r}",
                    truncated=True,
                )
            packets.append(packet)

        self.model.append_packets(packets)
        self.stats.add_packets(packets)
        self.stats_view.update_stats(self.stats)
        self.flow_manager.add_packets(packets)
        if packets:
            self._refresh_process_map()
        self._flow_dirty = True
        self._refresh_flow_table()
        self.captured_count = len(packets)
        self._update_counters(len(packets), 0, 0, 0)
        self.lbl_rows.setText(str(self.model.rowCount()))
        self._update_visible_count()
        self.btn_clear.setEnabled(bool(packets))

        self._offline_path = os.path.abspath(path)
        name = os.path.basename(self._offline_path)
        self.lbl_file.setText(f"当前来源: 离线文件 {name}")
        self.setWindowTitle(f"{_BASE_TITLE} - {name}")
        self._set_capturing(False)
        self._update_file_buttons()

        if offline.truncated:
            self._show_limit_notice(offline=True)

        link_name = _DATALINK_NAMES.get(offline.linktype,
                                       f"DLT={offline.linktype}")
        note = "（仅加载到缓存上限）" if offline.truncated else ""
        self.statusBar().showMessage(
            f"已打开 {name} | {link_name} | {len(packets)} 包{note}"
        )

    def save_all_packets(self) -> None:
        self._save_packets(list(self.model.packets), "全部")

    def save_displayed_packets(self) -> None:
        packets = []
        for row in range(self.proxy.rowCount()):
            source = self.proxy.mapToSource(self.proxy.index(row, 0))
            packet = self.model.packet_at(source.row())
            if packet is not None:
                packets.append(packet)
        self._save_packets(packets, "显示结果")

    def _save_packets(self, packets: list, label: str) -> None:
        if not packets:
            QMessageBox.warning(self, "没有可保存的包", "当前列表为空。")
            return
        if self._worker is not None:
            QMessageBox.warning(self, "正在抓包", "请先停止抓包再保存文件。")
            return

        if self._offline_path:
            default = os.path.basename(self._offline_path)
        else:
            default = datetime.now().strftime("capture_%Y%m%d_%H%M%S.pcap")
        path, _selected = QFileDialog.getSaveFileName(
            self,
            f"保存{label}包为 pcap",
            default,
            "pcap 文件 (*.pcap);;所有文件 (*)",
        )
        if not path:
            return
        if not os.path.splitext(path)[1]:
            path += ".pcap"

        try:
            count = write_pcap(path, packets)
        except PcapWriteError as exc:
            QMessageBox.critical(self, "保存 pcap 失败", str(exc))
            return
        self.statusBar().showMessage(
            f"已保存{label} {count} 包到 {os.path.basename(path)}"
        )

    def _show_limit_notice(self, offline: bool = False) -> None:
        if self._limit_warned:
            return
        self._limit_warned = True
        if offline:
            message = (
                f"已达到缓存上限 {self.max_packets} 包，"
                "文件剩余部分未加载"
            )
        else:
            message = (
                f"已达到缓存上限 {self.max_packets} 包，"
                "后续包不再加入列表（抓包统计仍继续）"
            )
        self.lbl_limit_notice.setText(message)
        self.lbl_limit_notice.setVisible(True)
        self.statusBar().showMessage(message)

    def _update_file_buttons(self) -> None:
        active = self._worker is not None
        has_packets = self.model.rowCount() > 0
        self.btn_open.setEnabled(not active)
        self.btn_save_all.setEnabled(has_packets and not active)
        self.btn_save_visible.setEnabled(has_packets and not active)

    # ---------------------------------------------------------------- flows
    def _schedule_flow_refresh(self) -> None:
        self._flow_dirty = True
        if (
            self.bottom_tabs.currentWidget() is self.flow_view
            and not self._flow_timer.isActive()
        ):
            self._flow_timer.start()

    def _refresh_flow_table(self) -> None:
        if not self._flow_dirty:
            return
        self._flow_dirty = False
        self.flow_view.set_flows(self.flow_manager.flows_sorted())

    def _on_bottom_tab_changed(self, index: int) -> None:
        if self.bottom_tabs.widget(index) is not self.flow_view:
            return
        if self._flow_dirty:
            self._refresh_flow_table()
        if (
            self.flow_manager.flows
            and self.process_map.last_refresh_ts == 0.0
        ):
            self._refresh_process_map()

    def _refresh_process_map(self) -> None:
        count = self.process_map.refresh()
        self.flow_manager.apply_process_map(self.process_map)
        self.flow_view.update_processes()
        if not self.table.isColumnHidden(COL_PROCESS):
            self.model.refresh_process_column()
        if self.process_map.last_error:
            self.flow_view.set_process_status(
                f"进程映射: {self.process_map.last_error}", error=True
            )
            return
        stamp = datetime.now().strftime("%H:%M:%S")
        if count:
            self.flow_view.set_process_status(
                f"进程映射: {count} 个 TCP 端点 | 更新 {stamp}"
            )
        else:
            self.flow_view.set_process_status(
                "进程映射: 未找到 TCP 连接（可尝试以管理员身份运行）"
                f" | 更新 {stamp}"
            )

    def _on_process_column_toggled(self, visible: bool) -> None:
        self.table.setColumnHidden(COL_PROCESS, not visible)
        if visible:
            self.table.setColumnWidth(COL_PROCESS, 170)
            self.model.refresh_process_column()

    def _show_flow_packets(self, flow) -> None:
        if flow is None:
            return
        if self.edit_display_filter.text().strip():
            self.clear_display_filter()
        key = flow.key
        self.proxy.set_packet_filter(lambda packet: packet.flow_key == key)
        self.table.sortByColumn(COL_NO, Qt.AscendingOrder)
        self.table.clearSelection()
        self.detail.clear_packet()
        self.hex_view.set_packet(None)
        self._update_visible_count()
        if flow.packets:
            self._select_packet_index(flow.packets[0].index)
        self.statusBar().showMessage(
            f"显示所选流 {flow.protocol} "
            f"{endpoint_text(flow.src_ip, flow.src_port)} ↔ "
            f"{endpoint_text(flow.dst_ip, flow.dst_port)} | "
            f"{self.proxy.rowCount()} 包（点“清除”恢复全部）"
        )

    def _jump_to_packet(self, packet_index: int) -> None:
        if not self._select_packet_index(packet_index):
            self.statusBar().showMessage(
                f"无法定位包 #{packet_index}，可能已被缓存上限截断"
            )

    def _select_packet_index(self, packet_index: int) -> bool:
        source_row = None
        for row, packet in enumerate(self.model.packets):
            if packet.index == packet_index:
                source_row = row
                break
        if source_row is None:
            return False

        source = self.model.index(source_row, 0)
        proxy = self.proxy.mapFromSource(source)
        if not proxy.isValid():
            self.clear_display_filter()
            proxy = self.proxy.mapFromSource(source)
        if not proxy.isValid():
            return False
        self.table.selectRow(proxy.row())
        self.table.scrollTo(proxy, QAbstractItemView.PositionAtCenter)
        self.table.setFocus()
        # selectRow() does not emit currentRowChanged when the row is already
        # current, and callers clear the detail panes before filtering.
        self._on_current_row_changed(self.table.currentIndex(), None)
        return True

    # -------------------------------------------------------------- display
    def apply_display_filter(self) -> None:
        text = self.edit_display_filter.text().strip()
        if not text:
            self.clear_display_filter()
            return
        try:
            compiled = compile_display_filter(text)
        except FilterSyntaxError as exc:
            self._set_filter_error(str(exc))
            return

        self._set_filter_error("")
        self.proxy.set_packet_filter(compiled.predicate)
        self.table.setCurrentIndex(QModelIndex())
        self.detail.clear_packet()
        self.hex_view.set_packet(None)
        self._update_visible_count()
        self.statusBar().showMessage(
            f"显示过滤已应用: {text} | 显示 {self.proxy.rowCount()} / "
            f"{self.model.rowCount()} 包"
        )

    def clear_display_filter(self) -> None:
        self.edit_display_filter.clear()
        self.proxy.set_packet_filter(None)
        self._set_filter_error("")
        self._update_visible_count()
        self.combo_display_presets.setCurrentIndex(0)

    def _on_filter_text_changed(self, text: str) -> None:
        del text
        if self.lbl_filter_error.isVisible():
            self._set_filter_error("")

    def _on_display_preset(self, index: int) -> None:
        if index <= 0:
            return
        self.edit_display_filter.setText(self.combo_display_presets.itemText(index))
        self.combo_display_presets.setCurrentIndex(0)
        self.apply_display_filter()

    def _set_filter_error(self, message: str) -> None:
        self.lbl_filter_error.setText(message)
        self.lbl_filter_error.setVisible(bool(message))
        if message:
            self.edit_display_filter.setStyleSheet(
                "border: 1px solid #c62828; background: #fff1f1;"
            )
        else:
            self.edit_display_filter.setStyleSheet("")

    def _update_visible_count(self) -> None:
        self.lbl_visible.setText(str(self.proxy.rowCount()))

    def _on_opened(self, device_name: str, datalink: int) -> None:
        link_name = _DATALINK_NAMES.get(datalink, f"DLT={datalink}")
        bpf_note = (
            f" | BPF: {self._active_capture_filter}"
            if self._active_capture_filter
            else ""
        )
        self.statusBar().showMessage(
            f"抓包中 | {device_name} | 链路类型: {link_name}{bpf_note}"
        )

    def _on_packets_ready(self, packets: list) -> None:
        if not packets:
            return
        self.stats.add_packets(packets)
        remaining = self.max_packets - self.model.rowCount()
        if remaining <= 0:
            self._show_limit_notice()
            return
        accepted = packets[:remaining]
        if len(accepted) < len(packets):
            self._show_limit_notice()

        scrollbar = self.table.verticalScrollBar()
        at_bottom = scrollbar.value() >= scrollbar.maximum() - 2
        self.model.append_packets(accepted)
        self.flow_manager.add_packets(accepted)
        self._schedule_flow_refresh()
        self.lbl_rows.setText(str(self.model.rowCount()))
        self._update_visible_count()
        self.btn_clear.setEnabled(self.model.rowCount() > 0)
        self._update_file_buttons()
        if at_bottom:
            self.table.scrollToBottom()

    def _on_stats(
        self,
        captured: int,
        received: int,
        dropped: int,
        if_dropped: int,
    ) -> None:
        self.captured_count = captured
        self._update_counters(captured, received, dropped, if_dropped)
        self.stats_view.update_stats(self.stats)

    def _update_counters(
        self,
        captured: int,
        received: int,
        dropped: int,
        if_dropped: int,
    ) -> None:
        self.lbl_captured.setText(str(captured))
        self.lbl_received.setText(str(received))
        self.lbl_dropped.setText(str(dropped))
        self.lbl_ifdropped.setText(str(if_dropped))

    def _on_current_row_changed(self, current, previous) -> None:
        del previous
        if not current.isValid():
            self.detail.clear_packet()
            self.hex_view.set_packet(None)
            return
        source = self.proxy.mapToSource(current)
        packet = self.model.packet_at(source.row())
        if packet is None:
            self.detail.clear_packet()
            self.hex_view.set_packet(None)
            return
        self.detail.set_packet(packet)
        self.hex_view.set_packet(packet)

    def _on_error(self, message: str) -> None:
        self.statusBar().showMessage("抓包出错，已停止")
        QMessageBox.critical(self, "抓包错误", message)

    def _on_worker_finished(self) -> None:
        worker = self._worker
        self._worker = None
        if worker is not None:
            worker.deleteLater()
        self._set_capturing(False)
        self._update_file_buttons()
        self.stats_view.update_stats(self.stats)
        if self.flow_manager.flows:
            self._refresh_process_map()
        self._flow_dirty = True
        self._refresh_flow_table()
        self.statusBar().showMessage(
            f"已停止 | 本次抓到 {self.captured_count} 个原始帧 | "
            f"列表 {self.model.rowCount()} 包 | 显示 {self.proxy.rowCount()} 包 | "
            f"流 {len(self.flow_manager.flows)} 条"
        )

    def _set_capturing(self, capturing: bool) -> None:
        has_device = self.combo_devices.count() > 0
        self.btn_start.setEnabled(
            self._capture_available
            and has_device
            and not capturing
            and self._offline_path is None
        )
        self.btn_stop.setEnabled(capturing)
        self.combo_devices.setEnabled(not capturing)
        self.btn_refresh.setEnabled(not capturing)
        self.combo_capture_filter.setEnabled(not capturing)
        self.btn_clear.setEnabled(
            self.model.rowCount() > 0 or self._offline_path is not None
        )
        if capturing:
            self._process_timer.start()
        else:
            self._process_timer.stop()
        self._update_file_buttons()

    # --------------------------------------------------------------- close
    def closeEvent(self, event) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            if not self._worker.wait(2000):
                self._worker.terminate()
                self._worker.wait(500)
            self._worker = None
        event.accept()
