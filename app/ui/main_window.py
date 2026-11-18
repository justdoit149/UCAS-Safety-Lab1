"""M1 main window: device selection, start/stop and raw frame counters."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
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

_DATALINK_NAMES = {
    0: "DLT_NULL（回环）",
    1: "DLT_EN10MB（以太网）",
    12: "DLT_RAW（裸 IP）",
}


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("1A 网络嗅探器 - M1 抓包骨架")
        self.resize(920, 460)

        self._worker: CaptureWorker | None = None
        self._capture_available = False
        self.captured_count = 0

        self._build_ui()
        self._load_devices()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        central = QWidget(self)
        root = QVBoxLayout(central)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(12)

        device_row = QHBoxLayout()
        device_row.addWidget(QLabel("网卡:"))
        self.combo_devices = QComboBox()
        self.combo_devices.setMinimumWidth(500)
        device_row.addWidget(self.combo_devices, 1)
        self.btn_refresh = QPushButton("刷新网卡")
        device_row.addWidget(self.btn_refresh)
        root.addLayout(device_row)

        control_row = QHBoxLayout()
        self.btn_start = QPushButton("开始抓包")
        self.btn_stop = QPushButton("停止抓包")
        self.btn_stop.setEnabled(False)
        control_row.addWidget(self.btn_start)
        control_row.addWidget(self.btn_stop)
        control_row.addStretch(1)
        root.addLayout(control_row)

        stats_box = QGroupBox("抓包统计")
        stats_form = QFormLayout(stats_box)
        self.lbl_captured = QLabel("0")
        self.lbl_received = QLabel("0")
        self.lbl_dropped = QLabel("0")
        self.lbl_ifdropped = QLabel("0")
        stats_form.addRow("已抓到原始帧:", self.lbl_captured)
        stats_form.addRow("驱动接收:", self.lbl_received)
        stats_form.addRow("驱动丢弃:", self.lbl_dropped)
        stats_form.addRow("网卡丢弃:", self.lbl_ifdropped)
        root.addWidget(stats_box)

        note = QLabel(
            "M1 只验证 Npcap 抓包、网卡枚举和原始帧计数。"
            "协议解析、三栏界面、过滤与流追踪将在后续里程碑实现。"
        )
        note.setWordWrap(True)
        note.setStyleSheet("color: #666;")
        root.addWidget(note)
        root.addStretch(1)

        self.setCentralWidget(central)
        self.statusBar().showMessage("正在检测 Npcap...")

        self.btn_refresh.clicked.connect(self._load_devices)
        self.btn_start.clicked.connect(self.start_capture)
        self.btn_stop.clicked.connect(self.stop_capture)

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

        self.captured_count = 0
        self._update_counters(0, 0, 0, 0)

        self._worker = CaptureWorker(device_name, parent=self)
        self._worker.opened.connect(self._on_opened)
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

    def _on_opened(self, device_name: str, datalink: int) -> None:
        link_name = _DATALINK_NAMES.get(datalink, f"DLT={datalink}")
        self.statusBar().showMessage(
            f"抓包中 | {device_name} | 链路类型: {link_name}"
        )

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
            f"已停止 | 本次抓到 {self.captured_count} 个原始帧"
        )

    def _set_capturing(self, capturing: bool) -> None:
        has_device = self.combo_devices.count() > 0
        self.btn_start.setEnabled(self._capture_available and has_device and not capturing)
        self.btn_stop.setEnabled(capturing)
        self.combo_devices.setEnabled(not capturing)
        self.btn_refresh.setEnabled(not capturing)

    # --------------------------------------------------------------- close
    def closeEvent(self, event) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            if not self._worker.wait(2000):
                self._worker.terminate()
                self._worker.wait(500)
            self._worker = None
        event.accept()
