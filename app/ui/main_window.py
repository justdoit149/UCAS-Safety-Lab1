"""M2 main window: packet list, protocol detail tree and hex dump."""

from __future__ import annotations

from PySide6.QtCore import QSortFilterProxyModel, Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
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
        self.setWindowTitle("1A 网络嗅探器 - M2 协议解析")
        self.resize(1280, 820)

        self._worker: CaptureWorker | None = None
        self._capture_available = False
        self.captured_count = 0

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

        self._splitters = QSplitter(Qt.Vertical)
        self._splitters.setChildrenCollapsible(False)

        self.table = QTableView()
        self.model = PacketTableModel(self)
        self.proxy = QSortFilterProxyModel(self)
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
        for caption, label in (
            ("已捕获帧:", self.lbl_captured),
            ("列表包数:", self.lbl_rows),
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

        self.clear_packets()
        self.captured_count = 0
        self._update_counters(0, 0, 0, 0)

        self._worker = CaptureWorker(device_name, parent=self)
        self._worker.opened.connect(self._on_opened)
        self._worker.packets_ready.connect(self._on_packets_ready)
        self._worker.stats_ready.connect(self._on_stats)
        self._worker.error.connect(self._on_error)
        self._worker.finished.connect(self._on_worker_finished)

        self._set_capturing(True)
        self.statusBar().showMessage(f"正在打开网卡: {device_name}")
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
        self.btn_clear.setEnabled(False)

    def _on_opened(self, device_name: str, datalink: int) -> None:
        link_name = _DATALINK_NAMES.get(datalink, f"DLT={datalink}")
        self.statusBar().showMessage(
            f"抓包中 | {device_name} | 链路类型: {link_name}"
        )

    def _on_packets_ready(self, packets: list) -> None:
        if not packets:
            return
        scrollbar = self.table.verticalScrollBar()
        at_bottom = scrollbar.value() >= scrollbar.maximum() - 2
        self.model.append_packets(packets)
        self.lbl_rows.setText(str(self.model.rowCount()))
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
            f"列表 {self.model.rowCount()} 包"
        )

    def _set_capturing(self, capturing: bool) -> None:
        has_device = self.combo_devices.count() > 0
        self.btn_start.setEnabled(
            self._capture_available and has_device and not capturing
        )
        self.btn_stop.setEnabled(capturing)
        self.combo_devices.setEnabled(not capturing)
        self.btn_refresh.setEnabled(not capturing)
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
