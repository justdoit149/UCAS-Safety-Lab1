"""Protocol detail tree.

Each item stores the byte range of its protocol/field in the frame.  Selecting
an item tells the hex view which bytes to highlight.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem

from app.core.models import Field, Layer, Packet


class DetailView(QTreeWidget):
    field_selected = Signal(int, int)  # offset, length

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderLabels(["字段", "值"])
        self.setRootIsDecorated(True)
        self.setAlternatingRowColors(True)
        self.setUniformRowHeights(True)
        self.setColumnWidth(0, 250)
        self.setColumnWidth(1, 360)
        self.currentItemChanged.connect(self._on_current_item_changed)

    # ------------------------------------------------------------------ API
    def set_packet(self, packet: Packet | None) -> None:
        self.blockSignals(True)
        try:
            self.clear()
            if packet is not None:
                for layer in packet.layers:
                    self.addTopLevelItem(self._make_layer_item(layer, packet))
                self.expandToDepth(0)
        finally:
            self.blockSignals(False)
        self.field_selected.emit(0, 0)

    def clear_packet(self) -> None:
        self.blockSignals(True)
        try:
            self.clear()
        finally:
            self.blockSignals(False)
        self.field_selected.emit(0, 0)

    # -------------------------------------------------------------- helpers
    @staticmethod
    def _make_layer_item(layer: Layer, packet: Packet) -> QTreeWidgetItem:
        item = QTreeWidgetItem([layer.name, f"{layer.length} bytes"])
        item.setData(0, Qt.UserRole, (layer.offset, layer.length))
        item.setToolTip(0, layer.name)
        item.setToolTip(1, packet.summary)
        for field in layer.fields:
            item.addChild(DetailView._make_field_item(field))
        return item

    @staticmethod
    def _make_field_item(field: Field) -> QTreeWidgetItem:
        value = field.value if field.value else "-"
        item = QTreeWidgetItem([field.name, value])
        item.setData(0, Qt.UserRole, (field.offset, field.length))
        item.setToolTip(0, f"{field.name} @ {field.offset}+{field.length}")
        item.setToolTip(1, value)
        for child in field.children:
            item.addChild(DetailView._make_field_item(child))
        return item

    def _on_current_item_changed(
        self, current: QTreeWidgetItem | None, previous: QTreeWidgetItem | None
    ) -> None:
        del previous
        if current is None:
            self.field_selected.emit(0, 0)
            return
        value = current.data(0, Qt.UserRole)
        if not value:
            self.field_selected.emit(0, 0)
            return
        offset, length = value
        self.field_selected.emit(int(offset), int(length))
