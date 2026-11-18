"""Read-only hex dump with byte-range highlighting.

A QPlainTextEdit keeps scrolling and text selection for free; ``_byte_positions``
records where each byte lives in the document so a field can highlight both
the hex column and the ASCII column.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QTextCursor
from PySide6.QtWidgets import QPlainTextEdit, QTextEdit

from app.core.models import Packet

BYTES_PER_ROW = 16
_HIGHLIGHT_BG = QColor("#ffe082")
_HIGHLIGHT_FG = QColor("#212121")


class HexView(QPlainTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setUndoRedoEnabled(False)
        self.setLineWrapMode(QPlainTextEdit.NoWrap)
        font = QFont("Consolas", 10)
        font.setStyleHint(QFont.Monospace)
        self.setFont(font)
        self.setStyleSheet(
            "QPlainTextEdit { background: #fbfbfb; border: 1px solid #c8c8c8; "
            "selection-background-color: #bbdefb; }"
        )
        self._byte_positions: list[tuple[int, int]] = []

    # ------------------------------------------------------------------ API
    def set_packet(self, packet: Packet | None) -> None:
        self.setExtraSelections([])
        self._byte_positions = []
        if packet is None or not packet.raw:
            self.setPlainText("")
            return

        lines: list[str] = []
        positions: list[tuple[int, int]] = []
        doc_pos = 0
        raw = packet.raw

        for row_start in range(0, len(raw), BYTES_PER_ROW):
            chunk = raw[row_start : row_start + BYTES_PER_ROW]
            prefix = f"{row_start:08x}  "
            parts = [prefix]
            local_hex: list[tuple[int, int]] = []
            pos = len(prefix)

            for index, byte in enumerate(chunk):
                if index == 8:
                    parts.append(" ")
                    pos += 1
                local_hex.append((index, pos))
                parts.append(f"{byte:02x} ")
                pos += 3

            hex_text = "".join(parts)
            ascii_start = len(hex_text) + 2  # " |"
            ascii_text = "".join(
                chr(byte) if 32 <= byte < 127 else "." for byte in chunk
            )
            line = f"{hex_text} |{ascii_text}|"
            for index, hex_pos in local_hex:
                positions.append(
                    (doc_pos + hex_pos, doc_pos + ascii_start + index)
                )
            lines.append(line)
            doc_pos += len(line) + 1

        self.setPlainText("\n".join(lines))
        self._byte_positions = positions
        cursor = QTextCursor(self.document())
        cursor.movePosition(QTextCursor.Start)
        self.setTextCursor(cursor)

    def highlight(self, offset: int, length: int) -> None:
        if not self._byte_positions or length <= 0:
            self.setExtraSelections([])
            return

        start = max(0, offset)
        end = min(len(self._byte_positions), start + length)
        if start >= end:
            self.setExtraSelections([])
            return

        hex_start = self._byte_positions[start][0]
        hex_end = self._byte_positions[end - 1][0] + 2
        ascii_start = self._byte_positions[start][1]
        ascii_end = self._byte_positions[end - 1][1] + 1

        selections = []
        for begin, finish in ((hex_start, hex_end), (ascii_start, ascii_end)):
            selection = QTextEdit.ExtraSelection()
            cursor = QTextCursor(self.document())
            cursor.setPosition(begin)
            cursor.setPosition(finish, QTextCursor.KeepAnchor)
            selection.cursor = cursor
            selection.format.setBackground(_HIGHLIGHT_BG)
            selection.format.setForeground(_HIGHLIGHT_FG)
            selections.append(selection)
        self.setExtraSelections(selections)

        cursor = QTextCursor(self.document())
        cursor.setPosition(hex_start)
        self.setTextCursor(cursor)
        self.ensureCursorVisible()

    def clear_highlight(self) -> None:
        self.setExtraSelections([])
