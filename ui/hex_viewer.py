"""通用 Hex 查看器组件:虚拟滚动表格 + 跳转/搜索 + 光标处数据解释。"""

from __future__ import annotations

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor, QCursor, QFont, QFontMetrics
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
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


class HexViewer(QWidget):
    """Hex 查看器:表格 + 偏移跳转 + 搜索 + 数据检查器。"""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._data = b""
        self._matches: list[int] = []
        self._match_pos = -1
        self._jump_offset: int | None = None
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

    # ---------------- 数据 ----------------
    def set_data(self, data: bytes) -> None:
        self._data = data
        self._matches = []
        self._match_pos = -1
        self.match_label.setText("")
        self.model.set_data(data)
        self.inspector.setRowCount(0)

    def clear(self) -> None:
        self.set_data(b"")

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
        """根据鼠标在单元格内的水平位置估算具体字节,保证检查器显示的是点中的字节。"""
        row_start = index.row() * _BYTES_PER_ROW
        if index.column() != 1:
            return row_start
        rect = self.table.visualRect(index)
        if rect.isNull():
            return row_start
        x = self.table.viewport().mapFromGlobal(QCursor.pos()).x()
        char_w = QFontMetrics(self.table.font()).horizontalAdvance("0")
        if char_w <= 0:
            return row_start
        pos = int((x - rect.x()) / (char_w * 3))
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
