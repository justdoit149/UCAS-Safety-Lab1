"""M2 main window: packet list, protocol detail tree and hex dump."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

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
from app.services.capture import CaptureWorker
from app.ui.detail_view import DetailView
from app.ui.hex_view import HexView
from app.ui.packet_model import (
    COL_INFO,
    COL_NO,
    COL_TIME,
    PacketFilterProxyModel,
    PacketTableModel,
    SORT_ROLE,
)

_DATALINK_NAMES = {
    0: "DLT_NULL（回环）",
    1: "DLT_EN10MB（以太网）",
    12: "DLT_RAW（裸 IP）",
}


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("1A 网络嗅探器 - M3 过滤")
        self.resize(1280, 860)

        self._worker: CaptureWorker | None = None
        self._capture_available = False
        self.captured_count = 0
        self._active_capture_filter = ""

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

        stats_box = QGroupBox("抓包统计")
        stats_row = QHBoxLayout(stats_box)
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
        root.addWidget(stats_box)

        self.setCentralWidget(central)
        self.statusBar().showMessage("正在检测 Npcap...")

        self.btn_refresh.clicked.connect(self._load_devices)
        self.btn_start.clicked.connect(self.start_capture)
        self.btn_stop.clicked.connect(self.stop_capture)
        self.btn_clear.clicked.connect(self.clear_packets)
        self.btn_apply_filter.clicked.connect(self.apply_display_filter)
        self.btn_clear_filter.clicked.connect(self.clear_display_filter)
        self.edit_display_filter.returnPressed.connect(self.apply_display_filter)
        self.edit_display_filter.textChanged.connect(self._on_filter_text_changed)
        self.combo_display_presets.activated.connect(self._on_display_preset)
        self.detail.field_selected.connect(self.hex_view.highlight)
        self.table.selectionModel().currentRowChanged.connect(
            self._on_current_row_changed
        )

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
        if self._worker is not None:
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
        self.table.clearSelection()
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
        scrollbar = self.table.verticalScrollBar()
        at_bottom = scrollbar.value() >= scrollbar.maximum() - 2
        self.model.append_packets(packets)
        self.lbl_rows.setText(str(self.model.rowCount()))
        self._update_visible_count()
        self.btn_clear.setEnabled(self.model.rowCount() > 0)
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
        self.statusBar().showMessage(
            f"已停止 | 本次抓到 {self.captured_count} 个原始帧 | "
            f"列表 {self.model.rowCount()} 包 | 显示 {self.proxy.rowCount()} 包"
        )

    def _set_capturing(self, capturing: bool) -> None:
        has_device = self.combo_devices.count() > 0
        self.btn_start.setEnabled(
            self._capture_available and has_device and not capturing
        )
        self.btn_stop.setEnabled(capturing)
        self.combo_devices.setEnabled(not capturing)
        self.btn_refresh.setEnabled(not capturing)
        self.combo_capture_filter.setEnabled(not capturing)
        self.btn_clear.setEnabled(self.model.rowCount() > 0)

    # --------------------------------------------------------------- close
    def closeEvent(self, event) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            if not self._worker.wait(2000):
                self._worker.terminate()
                self._worker.wait(500)
            self._worker = None
        event.accept()
