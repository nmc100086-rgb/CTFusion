"""通用 Hex 查看器组件:虚拟滚动表格 + 跳转/搜索 + 数据解释 + 双击编辑。"""

from __future__ import annotations

from PySide6.QtCore import QAbstractTableModel, QEvent, QModelIndex, QRect, Qt, Signal
from PySide6.QtGui import (
    QColor,
    QCursor,
    QFont,
    QFontMetrics,
    QKeySequence,
    QPalette,
    QShortcut,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.analysis import interpret_at
from ui.highlight import has_flag

_BYTES_PER_ROW = 16


class HexTableModel(QAbstractTableModel):
    """按需取数的 Hex 模型:大文件也不会卡(不缓存每行文本)。"""

    COLS = 3  # 偏移 | 十六进制 | ASCII

    def __init__(self, data: bytes = b"") -> None:
        super().__init__()
        self._data = data
        self._highlight_rows: set[int] = set()
        self._highlight_bytes: set[int] = set()

    def set_data(self, data: bytes) -> None:
        self.beginResetModel()
        self._data = data
        self._highlight_rows.clear()
        self._highlight_bytes.clear()
        self.endResetModel()

    def set_search_matches(self, offsets: list[int], length: int) -> None:
        rows: set[int] = set()
        bytes_set: set[int] = set()
        for offset in offsets:
            first_row = offset // _BYTES_PER_ROW
            last_row = (offset + max(1, length) - 1) // _BYTES_PER_ROW
            rows.update(range(first_row, last_row + 1))
            bytes_set.update(range(offset, offset + max(1, length)))
        self._highlight_rows = rows
        self._highlight_bytes = bytes_set
        if self._data:
            self.dataChanged.emit(self.index(0, 0),
                                  self.index(self.rowCount() - 1, self.COLS - 1))

    def clear_highlights(self) -> None:
        if not self._highlight_rows and not self._highlight_bytes:
            return
        self._highlight_rows.clear()
        self._highlight_bytes.clear()
        if self._data:
            self.dataChanged.emit(self.index(0, 0),
                                  self.index(self.rowCount() - 1, self.COLS - 1))

    def match_bytes_for_row(self, row: int) -> set[int]:
        """返回该行内的字节位置(0~15),不是全局 offset。"""
        start = row * _BYTES_PER_ROW
        return {i - start for i in range(start, start + _BYTES_PER_ROW)
                if i in self._highlight_bytes}

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
        if role == Qt.BackgroundRole and index.column() == 2 and has_flag(
                "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)):
            return QColor("#6f5200")
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


class HexDelegate(QStyledItemDelegate):
    """在十六进制/ASCII 单元格里精确涂亮命中的字节。"""

    def paint(self, painter, option, index) -> None:  # noqa: N802
        model = index.model()
        if (index.column() not in (1, 2)
                or not isinstance(model, HexTableModel)
                or not model._highlight_bytes):
            super().paint(painter, option, index)
            return
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        style = opt.widget.style() if opt.widget is not None else None
        if style is not None:
            style.drawPrimitive(QStyle.PE_PanelItemViewItem, opt, painter, opt.widget)
        text = index.data(Qt.DisplayRole) or ""
        row = index.row()
        matched = model.match_bytes_for_row(row)
        if not matched:
            painter.save()
            painter.setPen(opt.palette.color(QPalette.Text))
            painter.drawText(opt.rect.adjusted(4, 0, -4, 0),
                             Qt.AlignVCenter, text)
            painter.restore()
            return
        font = opt.font
        metrics = QFontMetrics(font)
        painter.save()
        painter.setFont(font)
        x0 = opt.rect.left() + 4
        y0 = opt.rect.top()
        height = opt.rect.height()
        # 命中字节的背景
        if index.column() == 1:
            for pos in matched:
                start = pos * 3
                x = x0 + metrics.horizontalAdvance(text[:start])
                width = metrics.horizontalAdvance(text[start:start + 2])
                painter.fillRect(QRect(x, y0, width, height), QColor("#8a6a00"))
        else:
            for pos in matched:
                if pos >= len(text):
                    continue
                x = x0 + metrics.horizontalAdvance(text[:pos])
                width = metrics.horizontalAdvance(text[pos])
                painter.fillRect(QRect(x, y0, width, height), QColor("#8a6a00"))
        painter.setPen(opt.palette.color(QPalette.Text))
        painter.drawText(opt.rect.adjusted(4, 0, -4, 0), Qt.AlignVCenter, text)
        painter.restore()


class HexViewer(QWidget):
    """Hex 查看器:表格 + 偏移跳转 + 搜索 + 双击编辑 + 撤销/保存。"""

    dataEdited = Signal()
    saveRequested = Signal()
    saveAsRequested = Signal()
    editBlocked = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._data = b""
        self._matches: list[int] = []
        self._match_pos = -1
        self._search_key: tuple[str, str, int] | None = None
        self._jump_offset: int | None = None
        self._undo: list[tuple[int, bytes, bytes]] = []
        self._redo: list[tuple[int, bytes, bytes]] = []
        self._modified = False
        self._read_only = False
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
        self.search_edit.setPlaceholderText("ASCII 文本(忽略大小写)")
        self.search_edit.returnPressed.connect(self._on_search)
        bar.addWidget(self.search_edit)

        self.search_mode = QComboBox()
        self.search_mode.addItem("ASCII", "ascii")
        self.search_mode.addItem("Hex", "hex")
        self.search_mode.currentIndexChanged.connect(self._on_search_mode_changed)
        bar.addWidget(self.search_mode)

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
        self.btn_save = QPushButton("覆盖保存")
        self.btn_save.setToolTip("把修改写回源文件(Ctrl+S)")
        self.btn_save.clicked.connect(self._request_save)
        bar.addWidget(self.btn_save)
        self.btn_save_as = QPushButton("保存副本…")
        self.btn_save_as.setToolTip("保存为新文件,不覆盖源文件")
        self.btn_save_as.clicked.connect(lambda: self.saveAsRequested.emit())
        bar.addWidget(self.btn_save_as)

        self.match_label = QLabel("")
        bar.addWidget(self.match_label)
        bar.addStretch()
        layout.addLayout(bar)

        self.model = HexTableModel()
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setItemDelegate(HexDelegate(self.table))
        # 搜索时需要只选中命中的单元格,不能用整行选中盖住精确高亮。
        self.table.setSelectionBehavior(QAbstractItemView.SelectItems)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.setFont(QFont("Consolas"))
        self.table.selectionModel().currentChanged.connect(self._on_current_changed)
        # QTableView 会吃掉双击事件,在 viewport 上装事件过滤器才能拿到精确坐标。
        self.table.viewport().installEventFilter(self)
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
    def set_data(self, data: bytes, read_only: bool = False) -> None:
        self._data = data
        self._read_only = read_only
        self._matches = []
        self._match_pos = -1
        self._search_key = None
        self._undo.clear()
        self._redo.clear()
        self._modified = False
        self.table.setToolTip(
            "只读文件:双击修改会被拒绝,可使用「保存副本…」" if read_only else "")
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
        if self._read_only:
            self.editBlocked.emit()
            return False
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
        if self._read_only:
            self.editBlocked.emit()
            return
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
        if self._read_only:
            self.editBlocked.emit()
            return
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
        if self._read_only:
            self.saveAsRequested.emit()
            return
        self.saveRequested.emit()

    def _update_state(self) -> None:
        self.btn_undo.setEnabled(bool(self._undo) and not self._read_only)
        self.btn_redo.setEnabled(bool(self._redo) and not self._read_only)
        self.btn_save.setEnabled(self._modified and not self._read_only)

    def _clear_search(self) -> None:
        self._matches = []
        self._match_pos = -1
        self._search_key = None
        self.model.clear_highlights()
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

    def eventFilter(self, watched, event) -> bool:  # noqa: N802
        if (watched is self.table.viewport()
                and event.type() == QEvent.MouseButtonDblClick
                and event.button() == Qt.LeftButton and self._data):
            pos = event.position().toPoint()
            index = self.table.indexAt(pos)
            if index.isValid():
                self._edit_byte(self._offset_from_pos(index, pos.x()))
                return True
        return super().eventFilter(watched, event)

    def _edit_byte(self, offset: int) -> None:
        if not self._data:
            return
        offset = max(0, min(offset, len(self._data) - 1))
        if self._read_only:
            QMessageBox.warning(
                self, "MiscKit",
                "当前文件是只读的,不能直接修改。\n"
                "可以双击前先复制一份,或使用「保存副本…」保存修改后的副本。")
            return
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

    def _on_search_mode_changed(self, _index: int = -1) -> None:
        mode = self.search_mode.currentData()
        self.search_edit.setPlaceholderText(
            "Hex 字节,如 FF D8 FF" if mode == "hex"
            else "ASCII 文本(忽略大小写)")
        self._clear_search()

    def _run_search(self, step: bool) -> bool:
        needle = self.search_edit.text()
        mode = self.search_mode.currentData() or "ascii"
        if not needle:
            self._clear_search()
            self.match_label.setText("请输入搜索内容")
            return False
        if mode == "hex":
            try:
                pattern = bytes.fromhex(needle)
            except ValueError:
                self.match_label.setText("Hex 格式错误,示例:FF D8 FF")
                return False
            haystack = self._data
            target = pattern
        else:
            pattern = needle.encode("utf-8")
            # bytes.lower() 对 ASCII 做大小写折叠;搜索 ASCII 时不区分大小写。
            haystack = self._data.lower()
            target = pattern.lower()
        if not pattern:
            self._clear_search()
            self.match_label.setText("请输入搜索内容")
            return False
        matches: list[int] = []
        start = 0
        while True:
            pos = haystack.find(target, start)
            if pos < 0:
                break
            matches.append(pos)
            start = pos + 1
        self._matches = matches
        self._match_pos = -1
        self._search_key = (needle, mode, len(self._data))
        if matches:
            self.model.set_search_matches(matches, len(pattern))
            self.match_label.setText(f"共 {len(matches)} 处命中")
            if step:
                self._step(1, ensure=False)
            return True
        self.model.clear_highlights()
        self.match_label.setText("未找到")
        return False

    def _on_search(self) -> None:
        self._run_search(step=True)

    def _step(self, delta: int, ensure: bool = True) -> None:
        key = (
            self.search_edit.text(),
            self.search_mode.currentData() or "ascii",
            len(self._data),
        )
        if ensure and key != self._search_key:
            if not self._run_search(step=False):
                return
        if not self._matches:
            return
        self._match_pos = (self._match_pos + delta) % len(self._matches)
        offset = self._matches[self._match_pos]
        self.match_label.setText(f"第 {self._match_pos + 1}/{len(self._matches)} 处 @ 0x{offset:X}")
        self.goto_offset(offset)
        # 选中单元格的底色会盖住精确字节高亮,搜索跳转后只保留当前单元格。
        self.table.clearSelection()

    def _copy_selection(self) -> None:
        indexes = self.table.selectionModel().selectedIndexes()
        rows = sorted({i.row() for i in indexes})
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
