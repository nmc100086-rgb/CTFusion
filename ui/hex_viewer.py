"""通用 Hex 查看器组件:虚拟滚动表格 + 跳转/搜索 + 数据解释 + 双击编辑。"""

from __future__ import annotations

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, Signal
from PySide6.QtGui import QColor, QCursor, QFont, QFontMetrics, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.analysis import interpret_at

_BYTES_PER_ROW = 16


class HexTableModel(QAbstractTableModel):
    """按需取数的 Hex 模型:大文件也不会卡(不缓存每行文本)。"""

    COLS = 3  # 偏移 | 十六进制 | ASCII

    def __init__(self, data: bytes = b"") -> None:
        super().__init__()
        self._data = data

    def set_data(self, data: bytes) -> None:
        self.beginResetModel()
        self._data = data
        self.endResetModel()

    @property
    def data_bytes(self) -> bytes:
        return self._data

    @property
    def bytes_per_row(self) -> int:
        return _BYTES_PER_ROW

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        if parent.isValid():
            return 0
        return (len(self._data) + _BYTES_PER_ROW - 1) // _BYTES_PER_ROW

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else self.COLS

    def headerData(self, section: int, orientation, role=Qt.DisplayRole):  # noqa: N802
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return ("偏移", "十六进制 (16 字节/行)", "ASCII")[section]
        return f"{section * _BYTES_PER_ROW:08X}"

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = index.row()
        start = row * _BYTES_PER_ROW
        chunk = self._data[start:start + _BYTES_PER_ROW]
        if role == Qt.DisplayRole:
            if index.column() == 0:
                return f"{start:08X}"
            if index.column() == 1:
                return " ".join(f"{b:02X}" for b in chunk)
            return "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        if role == Qt.ForegroundRole and index.column() == 0:
            return QColor("#7a7a7a")
        if role == Qt.FontRole:
            font = QFont("Consolas")
            font.setStyleHint(QFont.Monospace)
            return font
        return None

    def replace(self, offset: int, new: bytes) -> bool:
        """原位替换若干字节(不改变文件长度),返回是否真的发生变化。"""
        if not new or offset < 0 or offset + len(new) > len(self._data):
            return False
        if self._data[offset:offset + len(new)] == new:
            return False
        self._data = self._data[:offset] + new + self._data[offset + len(new):]
        first_row = offset // _BYTES_PER_ROW
        last_row = (offset + len(new) - 1) // _BYTES_PER_ROW
        self.dataChanged.emit(self.index(first_row, 1),
                              self.index(last_row, self.COLS - 1))
        return True


class HexViewer(QWidget):
    """Hex 查看器:表格 + 偏移跳转 + 搜索 + 双击编辑 + 撤销/保存。"""

    dataEdited = Signal()
    saveRequested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._data = b""
        self._matches: list[int] = []
        self._match_pos = -1
        self._jump_offset: int | None = None
        self._undo: list[tuple[int, bytes, bytes]] = []
        self._redo: list[tuple[int, bytes, bytes]] = []
        self._modified = False
        self._build_ui()

    # ---------------- UI ----------------
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        bar = QHBoxLayout()
        bar.addWidget(QLabel("跳转:"))
        self.goto_edit = QLineEdit()
        self.goto_edit.setPlaceholderText("偏移(支持 0x1A / 26)")
        self.goto_edit.setMaximumWidth(150)
        self.goto_edit.returnPressed.connect(self._on_goto)
        bar.addWidget(self.goto_edit)

        self.btn_goto = QPushButton("跳转")
        self.btn_goto.clicked.connect(self._on_goto)
        bar.addWidget(self.btn_goto)

        bar.addSpacing(12)
        bar.addWidget(QLabel("搜索:"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("文本,或勾选按 Hex 解析")
        self.search_edit.returnPressed.connect(self._on_search)
        bar.addWidget(self.search_edit)

        self.hex_mode = QCheckBox("Hex")
        bar.addWidget(self.hex_mode)

        self.btn_search = QPushButton("查找全部")
        self.btn_search.clicked.connect(self._on_search)
        bar.addWidget(self.btn_search)

        self.btn_prev = QPushButton("上一个")
        self.btn_prev.clicked.connect(lambda: self._step(-1))
        bar.addWidget(self.btn_prev)
        self.btn_next = QPushButton("下一个")
        self.btn_next.clicked.connect(lambda: self._step(1))
        bar.addWidget(self.btn_next)

        self.btn_copy = QPushButton("复制选区")
        self.btn_copy.setToolTip("把选中的字节复制为十六进制字符串")
        self.btn_copy.clicked.connect(self._copy_selection)
        bar.addWidget(self.btn_copy)

        bar.addSpacing(12)
        self.btn_undo = QPushButton("撤销")
        self.btn_undo.clicked.connect(self.undo)
        bar.addWidget(self.btn_undo)
        self.btn_redo = QPushButton("重做")
        self.btn_redo.clicked.connect(self.redo)
        bar.addWidget(self.btn_redo)
        self.btn_save = QPushButton("保存")
        self.btn_save.setToolTip("把修改写回文件(Ctrl+S)")
        self.btn_save.clicked.connect(self._request_save)
        bar.addWidget(self.btn_save)

        self.match_label = QLabel("")
        bar.addWidget(self.match_label)
        bar.addStretch()
        layout.addLayout(bar)

        self.model = HexTableModel()
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.setFont(QFont("Consolas"))
        self.table.selectionModel().currentChanged.connect(self._on_current_changed)
        layout.addWidget(self.table, 1)

        self.inspector = QTableWidget(0, 2)
        self.inspector.setHorizontalHeaderLabels(["类型", "值"])
        self.inspector.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.inspector.verticalHeader().setVisible(False)
        self.inspector.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.inspector.setMaximumHeight(170)
        layout.addWidget(self.inspector)

        QShortcut(QKeySequence.Undo, self, activated=self.undo)
        QShortcut(QKeySequence.Redo, self, activated=self.redo)
        QShortcut(QKeySequence.Save, self, activated=self._request_save)
        self._update_state()

    # ---------------- 数据 ----------------
    def set_data(self, data: bytes) -> None:
        self._data = data
        self._matches = []
        self._match_pos = -1
        self._undo.clear()
        self._redo.clear()
        self._modified = False
        self._update_state()
        self.match_label.setText("")
        self.model.set_data(data)
        self.inspector.setRowCount(0)

    def clear(self) -> None:
        self.set_data(b"")

    @property
    def data_bytes(self) -> bytes:
        return self._data

    @property
    def is_modified(self) -> bool:
        return self._modified

    def current_offset(self) -> int:
        index = self.table.currentIndex()
        if not index.isValid():
            return 0
        return index.row() * _BYTES_PER_ROW

    def goto_offset(self, offset: int) -> None:
        if not self._data:
            return
        offset = max(0, min(offset, len(self._data) - 1))
        row = offset // _BYTES_PER_ROW
        index = self.model.index(row, 1)
        self._jump_offset = offset  # 程序跳转时检查器显示精确字节
        self.table.setCurrentIndex(index)
        self.table.scrollTo(index, QAbstractItemView.PositionAtCenter)
        if self._jump_offset is not None:  # 索引未变化时不会触发信号
            self._jump_offset = None
            self._update_inspector(offset)

    # ---------------- 编辑 ----------------
    def apply_edit(self, offset: int, new: bytes) -> bool:
        if offset < 0 or offset + len(new) > len(self._data) or not new:
            return False
        old = self._data[offset:offset + len(new)]
        if not self.model.replace(offset, new):
            return False
        self._data = self.model.data_bytes
        self._undo.append((offset, old, new))
        self._redo.clear()
        self._modified = True
        self._update_state()
        self._clear_search()
        self.dataEdited.emit()
        return True

    def undo(self) -> None:
        if not self._undo:
            return
        offset, old, new = self._undo.pop()
        if self.model.replace(offset, old):
            self._data = self.model.data_bytes
            self._redo.append((offset, old, new))
            self._modified = True
            self._update_state()
            self._clear_search()
            self.dataEdited.emit()

    def redo(self) -> None:
        if not self._redo:
            return
        offset, old, new = self._redo.pop()
        if self.model.replace(offset, new):
            self._data = self.model.data_bytes
            self._undo.append((offset, old, new))
            self._modified = True
            self._update_state()
            self._clear_search()
            self.dataEdited.emit()

    def save_to(self, path: str) -> bool:
        try:
            with open(path, "wb") as f:
                f.write(self._data)
        except OSError as e:
            QMessageBox.warning(self, "MiscKit", f"保存失败:{e}")
            return False
        self._modified = False
        self._update_state()
        return True

    def _request_save(self) -> None:
        self.saveRequested.emit()

    def _update_state(self) -> None:
        self.btn_undo.setEnabled(bool(self._undo))
        self.btn_redo.setEnabled(bool(self._redo))
        self.btn_save.setEnabled(self._modified)

    def _clear_search(self) -> None:
        self._matches = []
        self._match_pos = -1
        self.match_label.setText("")

    # ---------------- 交互 ----------------
    def _on_goto(self) -> None:
        text = self.goto_edit.text().strip()
        if not text:
            return
        try:
            value = int(text, 16) if text.lower().startswith("0x") else int(text)
        except ValueError:
            self.match_label.setText("偏移格式错误")
            return
        self.goto_offset(value)

    def mouseDoubleClickEvent(self, event) -> None:  # noqa: N802
        index = self.table.indexAt(event.position().toPoint())
        if not index.isValid() or not self._data:
            super().mouseDoubleClickEvent(event)
            return
        offset = self._offset_from_pos(index, event.position().toPoint().x())
        old = self._data[offset]
        text, ok = QInputDialog.getText(
            self,
            "编辑字节",
            f"偏移 0x{offset:X} 当前值 0x{old:02X} ({old})\n"
            f"输入新的十六进制值 (00-FF):",
            text=f"{old:02X}",
        )
        if not ok:
            return
        try:
            value = int(text.strip().lower().removeprefix("0x"), 16)
        except ValueError:
            QMessageBox.warning(self, "MiscKit", "请输入 00-FF 之间的十六进制值")
            return
        if not 0 <= value <= 0xFF:
            QMessageBox.warning(self, "MiscKit", "字节值必须在 00-FF 之间")
            return
        if self.apply_edit(offset, bytes([value])):
            self.goto_offset(offset)
            self.match_label.setText(f"已修改 0x{offset:X}: 0x{old:02X} → 0x{value:02X}")

    def _on_current_changed(self, current: QModelIndex, _previous: QModelIndex) -> None:
        if not current.isValid():
            return
        if self._jump_offset is not None:
            offset = self._jump_offset
            self._jump_offset = None
        else:
            offset = self._offset_from_cursor(current)
        self._update_inspector(offset)

    def _offset_from_cursor(self, index: QModelIndex) -> int:
        """根据鼠标在单元格内的水平位置估算具体字节。"""
        x = self.table.viewport().mapFromGlobal(QCursor.pos()).x()
        return self._offset_from_pos(index, x)

    def _offset_from_pos(self, index: QModelIndex, x: int) -> int:
        row_start = index.row() * _BYTES_PER_ROW
        if index.column() not in (1, 2):
            return min(row_start, max(0, len(self._data) - 1))
        rect = self.table.visualRect(index)
        char_w = QFontMetrics(self.table.font()).horizontalAdvance("0")
        if rect.isNull() or char_w <= 0:
            return row_start
        if index.column() == 1:
            pos = int((x - rect.x()) / (char_w * 3))
        else:
            pos = int((x - rect.x()) / char_w)
        return min(row_start + max(0, min(pos, _BYTES_PER_ROW - 1)),
                   max(0, len(self._data) - 1))

    def _update_inspector(self, offset: int) -> None:
        rows = interpret_at(self._data, offset)
        self.inspector.setRowCount(len(rows))
        for i, (name, value) in enumerate(rows):
            self.inspector.setItem(i, 0, QTableWidgetItem(name))
            self.inspector.setItem(i, 1, QTableWidgetItem(value))

    def _on_search(self) -> None:
        needle = self.search_edit.text()
        if not needle:
            return
        if self.hex_mode.isChecked():
            try:
                pattern = bytes.fromhex(needle)
            except ValueError:
                self.match_label.setText("Hex 格式错误")
                return
        else:
            pattern = needle.encode("utf-8")
        self._matches = []
        start = 0
        while True:
            pos = self._data.find(pattern, start)
            if pos < 0:
                break
            self._matches.append(pos)
            start = pos + 1
        self._match_pos = -1
        if self._matches:
            self.match_label.setText(f"共 {len(self._matches)} 处命中")
            self._step(1)
        else:
            self.match_label.setText("未找到")

    def _step(self, delta: int) -> None:
        if not self._matches:
            return
        self._match_pos = (self._match_pos + delta) % len(self._matches)
        offset = self._matches[self._match_pos]
        self.match_label.setText(f"第 {self._match_pos + 1}/{len(self._matches)} 处 @ 0x{offset:X}")
        self.goto_offset(offset)

    def _copy_selection(self) -> None:
        rows = sorted({i.row() for i in self.table.selectionModel().selectedRows()})
        if not rows:
            index = self.table.currentIndex()
            if index.isValid():
                rows = [index.row()]
        chunks = []
        for row in rows:
            start = row * _BYTES_PER_ROW
            chunks.append(self._data[start:start + _BYTES_PER_ROW])
        if not chunks:
            return
        text = " ".join(f"{b:02X}" for b in b"".join(chunks))
        from PySide6.QtWidgets import QApplication

        QApplication.clipboard().setText(text)
        self.match_label.setText("已复制到剪贴板")
