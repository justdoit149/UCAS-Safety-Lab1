"""Statistics tab: protocol distribution and packet-rate charts."""

from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

from app.services.stats import CaptureStats

try:
    import pyqtgraph as pg
except ImportError:  # pragma: no cover - requirements.txt installs it
    pg = None


class StatsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(170)

        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(4)

        if pg is None:
            root.addWidget(
                QLabel("未安装 pyqtgraph，统计图表不可用。请执行 pip install pyqtgraph")
            )
            self.protocol_plot = None
            self.rate_plot = None
        else:
            pg.setConfigOptions(antialias=True, background="w", foreground="#333333")
            charts = QHBoxLayout()
            self.protocol_plot = pg.PlotWidget()
            self.protocol_plot.setTitle("协议分布")
            self.protocol_plot.setLabel("left", "包数")
            self.protocol_plot.setMenuEnabled(False)
            self.protocol_plot.setMouseEnabled(x=False, y=False)
            self.protocol_plot.showGrid(x=False, y=True, alpha=0.2)
            self.rate_plot = pg.PlotWidget()
            self.rate_plot.setTitle("包速率（最近 60 秒）")
            self.rate_plot.setLabel("left", "包/秒")
            self.rate_plot.setLabel("bottom", "时间（秒）")
            self.rate_plot.setMenuEnabled(False)
            self.rate_plot.setMouseEnabled(x=False, y=False)
            self.rate_plot.showGrid(x=True, y=True, alpha=0.2)
            charts.addWidget(self.protocol_plot, 1)
            charts.addWidget(self.rate_plot, 1)
            root.addLayout(charts, 1)

        summary = QHBoxLayout()
        self.lbl_total = QLabel("总包数: 0")
        self.lbl_bytes = QLabel("总字节: 0")
        self.lbl_protocols = QLabel("协议种类: 0")
        self.lbl_rate = QLabel("最近 1 秒: 0 包/秒")
        for label in (self.lbl_total, self.lbl_bytes, self.lbl_protocols,
                      self.lbl_rate):
            label.setStyleSheet("color: #555;")
            summary.addWidget(label)
        summary.addStretch(1)
        root.addLayout(summary)

    def update_stats(self, stats: CaptureStats) -> None:
        protocols = stats.protocol_counts()
        self.lbl_total.setText(f"总包数: {stats.total_packets}")
        self.lbl_bytes.setText(f"总字节: {stats.total_bytes}")
        self.lbl_protocols.setText(f"协议种类: {len(protocols)}")
        self.lbl_rate.setText(f"最近 1 秒: {stats.current_rate} 包/秒")

        if pg is None or self.protocol_plot is None:
            return

        top = protocols[:10]
        self.protocol_plot.clear()
        if top:
            xs = list(range(len(top)))
            ys = [count for _, count in top]
            self.protocol_plot.addItem(
                pg.BarGraphItem(
                    x=xs,
                    height=ys,
                    width=0.7,
                    brush=pg.mkBrush("#1565c0"),
                )
            )
            ticks = [[(index, name) for index, (name, _count) in enumerate(top)]]
            self.protocol_plot.getAxis("bottom").setTicks(ticks)
        else:
            self.protocol_plot.getAxis("bottom").setTicks([[]])

        xs, ys = stats.rate_series()
        self.rate_plot.clear()
        if xs:
            self.rate_plot.plot(
                xs,
                ys,
                pen=pg.mkPen("#1565c0", width=2),
                fillLevel=0,
                brush=pg.mkBrush(21, 101, 192, 40),
            )
