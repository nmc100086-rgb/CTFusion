"""通用 Hex 查看器组件:虚拟滚动表格 + 跳转/搜索 + 数据解释 + 双击编辑。"""

from __future__ import annotations

from bisect import bisect_right

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
    QMenu,
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
_TEXT_MARGIN = 4


class HexTableModel(QAbstractTableModel):
    """按需取数的 Hex 模型:大文件也不会卡(不缓存每行文本)。"""

    COLS = 3  # 偏移 | 十六进制 | ASCII

    def __init__(self, data: bytes = b"") -> None:
        super().__init__()
        self._data = data
        self._highlight_ranges: list[tuple[int, int]] = []
        self._highlight_starts: list[int] = []
        self._byte_selection: tuple[int, int] | None = None

    def set_data(self, data: bytes) -> None:
        self.beginResetModel()
        self._data = data
        self._highlight_ranges.clear()
        self._highlight_starts.clear()
        self._byte_selection = None
        self.endResetModel()

    def set_search_matches(self, offsets: list[int], length: int) -> None:
        size = max(1, length)
        self._highlight_ranges = [
            (offset, min(len(self._data), offset + size))
            for offset in offsets
            if 0 <= offset < len(self._data)
        ]
        self._highlight_starts = [first for first, _last in self._highlight_ranges]
        if self._data:
            self.dataChanged.emit(self.index(0, 0),
                                  self.index(self.rowCount() - 1, self.COLS - 1))

    def clear_highlights(self) -> None:
        if not self._highlight_ranges:
            return
        self._highlight_ranges.clear()
        self._highlight_starts.clear()
        if self._data:
            self.dataChanged.emit(self.index(0, 0),
                                  self.index(self.rowCount() - 1, self.COLS - 1))

    def match_bytes_for_row(self, row: int) -> set[int]:
        """返回该行内的字节位置(0~15),不是全局 offset。

        搜索可能有数万条命中;用 sorted starts 做二分,避免每个可见行
        都从头遍历全部命中区间。
        """
        if not self._highlight_ranges:
            return set()
        start = row * _BYTES_PER_ROW
        end = min(len(self._data), start + _BYTES_PER_ROW)
        index = bisect_right(self._highlight_starts, start) - 1
        if index < 0:
            index = 0
        matched: set[int] = set()
        for first, last in self._highlight_ranges[index:]:
            if last <= start:
                continue
            if first >= end:
                break
            matched.update(range(max(start, first) - start,
                                 min(end, last) - start))
        return matched

    def _emit_selection_rows(self, first_row: int, last_row: int) -> None:
        if not self._data or last_row < first_row:
            return
        last = min(last_row, self.rowCount() - 1)
        first = max(0, first_row)
        if last >= first:
            self.dataChanged.emit(self.index(first, 1), self.index(last, 2))

    def set_byte_selection(self, anchor: int, focus: int) -> None:
        """Set the byte range selected by mouse drag (inclusive offsets)."""
        if not self._data:
            self.clear_byte_selection()
            return
        start = max(0, min(anchor, focus, len(self._data) - 1))
        end = min(len(self._data), max(anchor, focus) + 1)
        new_range = (start, end)
        if new_range == self._byte_selection:
            return
        old = self._byte_selection
        self._byte_selection = new_range
        if old is None:
            self._emit_selection_rows(start // _BYTES_PER_ROW,
                                      (end - 1) // _BYTES_PER_ROW)
            return
        old_start, old_end = old
        # 只重绘边界行:选区内部已经画过,不必每次拖动都全量刷新。
        if start != old_start:
            self._emit_selection_rows(
                min(start, old_start) // _BYTES_PER_ROW,
                max(start, old_start) // _BYTES_PER_ROW)
        if end != old_end:
            self._emit_selection_rows(
                min(end - 1, old_end - 1) // _BYTES_PER_ROW,
                max(end - 1, old_end - 1) // _BYTES_PER_ROW)

    def clear_byte_selection(self) -> None:
        if self._byte_selection is None:
            return
        first, last = self._byte_selection
        self._byte_selection = None
        self._emit_selection_rows(first // _BYTES_PER_ROW,
                                  (last - 1) // _BYTES_PER_ROW)

    def selection_bytes_for_row(self, row: int) -> set[int]:
        if self._byte_selection is None:
            return set()
        start = row * _BYTES_PER_ROW
        end = min(len(self._data), start + _BYTES_PER_ROW)
        first, last = self._byte_selection
        if last <= start or first >= end:
            return set()
        return set(range(max(start, first) - start,
                         min(end, last) - start))

    @property
    def data_bytes(self) -> bytes:
        return self._data

    @property
    def _highlight_bytes(self) -> set[int]:
        """Compatibility helper for callers that need an explicit byte set."""
        result: set[int] = set()
        for first, last in self._highlight_ranges:
            result.update(range(first, last))
        return result

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
        # 不要返回独立的 QFont("Consolas") as FontRole:它的默认字号
        # 可能和表格字号不同,导致绘制宽度与命中测试/选区计算不一致。
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
                or not (model._highlight_ranges or model._byte_selection)):
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
        selected = model.selection_bytes_for_row(row)
        if not matched and not selected:
            painter.save()
            painter.setPen(opt.palette.color(QPalette.Text))
            painter.drawText(opt.rect.adjusted(_TEXT_MARGIN, 0, -_TEXT_MARGIN, 0),
                             Qt.AlignVCenter, text)
            painter.restore()
            return
        font = opt.font
        metrics = QFontMetrics(font)
        painter.save()
        painter.setFont(font)
        x0 = opt.rect.left() + _TEXT_MARGIN
        y0 = opt.rect.top()
        height = opt.rect.height()

        def fill_positions(positions: set[int], color: QColor) -> None:
            if index.column() == 1:
                for pos in positions:
                    start = pos * 3
                    if start >= len(text):
                        continue
                    x = x0 + metrics.horizontalAdvance(text[:start])
                    width = metrics.horizontalAdvance(text[start:start + 2])
                    painter.fillRect(QRect(x, y0, width, height), color)
            else:
                for pos in positions:
                    if pos >= len(text):
                        continue
                    x = x0 + metrics.horizontalAdvance(text[:pos])
                    width = metrics.horizontalAdvance(text[pos])
                    painter.fillRect(QRect(x, y0, width, height), color)

        # 鼠标拖选:先铺半透明蓝,再叠搜索命中黄;两者可同时看见。
        fill_positions(selected, QColor(37, 99, 235, 90))
        fill_positions(matched, QColor("#ffd54f"))
        painter.setPen(QColor("#111111"))
        painter.drawText(opt.rect.adjusted(_TEXT_MARGIN, 0, -_TEXT_MARGIN, 0),
                         Qt.AlignVCenter, text)
        painter.restore()


class HexViewer(QWidget):
    """Hex 查看器:表格 + 偏移跳转 + 搜索 + 双击编辑 + 撤销/保存。"""

    dataEdited = Signal()
    saveRequested = Signal()
    saveAsRequested = Signal()
    editBlocked = Signal()
    MAX_SEARCH_MATCHES = 20_000

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._data = b""
        self._original_data = b""
        self._matches: list[int] = []
        self._match_pos = -1
        self._search_key: tuple[str, str, int] | None = None
        self._jump_offset: int | None = None
        self._undo: list[tuple[int, bytes, bytes]] = []
        self._redo: list[tuple[int, bytes, bytes]] = []
        self._modified = False
        self._read_only = False
        self._copy_anchor: int | None = None
        self._copy_focus: int | None = None
        self._copy_column: int | None = None
        self._search_truncated = False
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
        self.btn_copy.setToolTip(
            "复制选中字节:Hex 列复制 HEX,ASCII 列复制 ASCII 文本;"
            "也支持 Ctrl+C 和右键菜单")
        self.btn_copy.clicked.connect(lambda: self._copy_selection())
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

        self.search_hint = QLabel("")
        self.search_hint.setWordWrap(True)
        self.search_hint.setStyleSheet(
            "color:#92400e; background:#fffbeb; border:1px solid #fde68a;"
            "border-radius:8px; padding:6px 10px;")
        self.search_hint.hide()
        layout.addWidget(self.search_hint)

        self.model = HexTableModel()
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setItemDelegate(HexDelegate(self.table))
        # 用自定义的字节级蓝色选区,而不是整格选中;否则 Hex 单元格的
        # 16 个字节会一起变成蓝色,看不出鼠标到底拖选了哪几个字节。
        self.table.setSelectionBehavior(QAbstractItemView.SelectItems)
        self.table.setSelectionMode(QAbstractItemView.NoSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.setFont(QFont("Consolas"))
        self._char_width = max(
            1, QFontMetrics(self.table.font()).horizontalAdvance("0"))
        # 偏移/ASCII 列固定宽度。用 ResizeToContents 时,每次拖动选区
        # 的 dataChanged 都会触发 Qt 重新测量整列所有行,大文件会明显卡顿。
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        self.table.setColumnWidth(0, self._char_width * 10)
        self.table.setColumnWidth(2, self._char_width * 18)
        self.table.selectionModel().currentChanged.connect(self._on_current_changed)
        # QTableView 会吃掉双击事件,在 viewport 上装事件过滤器才能拿到精确坐标。
        self.table.viewport().installEventFilter(self)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_copy_menu)
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
        # 只在表格获得焦点时接管 Ctrl+C,避免搜索框里的复制被拦截。
        self._copy_shortcut = QShortcut(QKeySequence.Copy, self.table)
        self._copy_shortcut.setContext(Qt.WidgetShortcut)
        self._copy_shortcut.activated.connect(self._copy_selection)
        self._update_state()

    # ---------------- 数据 ----------------
    def set_data(self, data: bytes, read_only: bool = False,
                 preserve_search: bool = False) -> None:
        search_text = self.search_edit.text() if preserve_search else ""
        search_mode = self.search_mode.currentData() if preserve_search else None
        self._data = data
        self._original_data = data
        self._read_only = read_only
        self._matches = []
        self._match_pos = -1
        self._search_key = None
        self._search_truncated = False
        self._undo.clear()
        self._redo.clear()
        self._modified = False
        self._copy_anchor = None
        self._copy_focus = None
        self._copy_column = None
        self.table.setToolTip(
            "只读文件:双击修改会被拒绝,可使用「保存副本…」" if read_only else "")
        self._update_state()
        self.match_label.setText("")
        self.search_hint.hide()
        self.model.set_data(data)
        self.inspector.setRowCount(0)
        if preserve_search and search_text.strip():
            index = self.search_mode.findData(search_mode)
            if index >= 0:
                self.search_mode.blockSignals(True)
                self.search_mode.setCurrentIndex(index)
                self.search_mode.blockSignals(False)
                self._on_search_mode_changed()
                self.search_edit.setText(search_text)
            self._run_search(step=False)

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

    def _clear_byte_selection(self) -> None:
        self._copy_anchor = None
        self._copy_focus = None
        self._copy_column = None
        self.model.clear_byte_selection()

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
        self._modified = self._data != self._original_data
        self._update_state()
        self._refresh_search_after_edit()
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
            self._modified = self._data != self._original_data
            self._update_state()
            self._refresh_search_after_edit()
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
            self._modified = self._data != self._original_data
            self._update_state()
            self._refresh_search_after_edit()
            self.dataEdited.emit()

    def save_to(self, path: str) -> bool:
        try:
            with open(path, "wb") as f:
                f.write(self._data)
        except OSError as e:
            QMessageBox.warning(self, "CTFusion", f"保存失败:{e}")
            return False
        self._original_data = self._data
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
        self._search_truncated = False
        self.model.clear_highlights()
        self.match_label.setText("")
        self.search_hint.hide()

    def _show_search_hint(self, text: str) -> None:
        self.search_hint.setText(text)
        self.search_hint.show()

    def _match_status_text(self) -> str:
        if not self._matches:
            return "未找到" if self.search_edit.text().strip() else ""
        suffix = (
            f" (已达 {self.MAX_SEARCH_MATCHES:,} 条上限)"
            if self._search_truncated else ""
        )
        if self._match_pos < 0:
            return f"共 {len(self._matches)} 处命中{suffix}"
        offset = self._matches[self._match_pos]
        return (
            f"第 {self._match_pos + 1}/{len(self._matches)} 处命中 "
            f"@ 0x{offset:X}{suffix}"
        )

    def _refresh_search_after_edit(self) -> None:
        """编辑/撤销后沿用当前搜索条件重新计算,而不是把搜索清空。"""
        if not self.search_edit.text().strip():
            self._clear_search()
            return
        old_offset = (
            self._matches[self._match_pos]
            if 0 <= self._match_pos < len(self._matches) else None
        )
        self._search_key = None
        self._run_search(step=False)
        if old_offset is not None:
            try:
                self._match_pos = self._matches.index(old_offset)
            except ValueError:
                self._match_pos = -1
            self.match_label.setText(self._match_status_text())

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
        if watched is self.table.viewport() and self._data:
            event_type = event.type()
            if event_type not in (
                    QEvent.MouseButtonDblClick,
                    QEvent.MouseButtonPress,
                    QEvent.MouseMove):
                return super().eventFilter(watched, event)
            pos = event.position().toPoint()
            index = self.table.indexAt(pos)
            if (event_type == QEvent.MouseButtonDblClick
                    and event.button() == Qt.LeftButton):
                if index.isValid():
                    self._edit_byte(self._offset_from_pos(index, pos.x()))
                    return True
            if (event_type == QEvent.MouseButtonPress
                    and event.button() == Qt.LeftButton):
                if index.isValid() and index.column() in (1, 2):
                    offset = self._offset_from_pos(index, pos.x())
                    self._copy_column = index.column()
                    if not (event.modifiers() & Qt.ShiftModifier):
                        self._copy_anchor = offset
                    elif self._copy_anchor is None:
                        self._copy_anchor = offset
                    self._copy_focus = offset
                    self.model.set_byte_selection(
                        self._copy_anchor, self._copy_focus)
                elif index.isValid() and index.column() == 0:
                    # 点偏移列时清掉字节选区,避免旧蓝底残留。
                    self._clear_byte_selection()
            if (event_type == QEvent.MouseMove
                    and event.buttons() & Qt.LeftButton and index.isValid()
                    and index.column() in (1, 2)):
                self._copy_focus = self._offset_from_pos(index, pos.x())
                if self._copy_anchor is None:
                    self._copy_anchor = self._copy_focus
                self.model.set_byte_selection(
                    self._copy_anchor, self._copy_focus)
        return super().eventFilter(watched, event)

    def _edit_byte(self, offset: int) -> None:
        if not self._data:
            return
        offset = max(0, min(offset, len(self._data) - 1))
        if self._read_only:
            QMessageBox.warning(
                self, "CTFusion",
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
            QMessageBox.warning(self, "CTFusion", "请输入 00-FF 之间的十六进制值")
            return
        if not 0 <= value <= 0xFF:
            QMessageBox.warning(self, "CTFusion", "字节值必须在 00-FF 之间")
            return
        if self.apply_edit(offset, bytes([value])):
            self.goto_offset(offset)
            changed = f"已修改 0x{offset:X}: 0x{old:02X} → 0x{value:02X}"
            search_status = self._match_status_text()
            self.match_label.setText(
                f"{changed}  |  搜索: {search_status}"
                if search_status else changed)

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
        if rect.isNull():
            return row_start
        text_x = rect.x() + _TEXT_MARGIN
        text = index.data(Qt.DisplayRole) or ""
        metrics = QFontMetrics(self.table.font())
        available = min(_BYTES_PER_ROW, max(0, len(self._data) - row_start))
        chosen = 0
        if index.column() == 1:
            # Hex 文本是 "41 42 ...";按每个前缀的真实 advance 命中。
            # 不能简单用 char_width*3:空格和数字的实际宽度可能不同,
            # 固定步长会随字节位置累积误差,到行尾就明显错位。
            for pos in range(available):
                start = pos * 3
                if start >= len(text):
                    break
                left = text_x + metrics.horizontalAdvance(text[:start])
                if x >= left:
                    chosen = pos
                else:
                    break
        else:
            for pos in range(min(available, len(text))):
                left = text_x + metrics.horizontalAdvance(text[:pos])
                if x >= left:
                    chosen = pos
                else:
                    break
        return min(row_start + chosen, max(0, len(self._data) - 1))

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
            self._show_search_hint(
                "请输入要搜索的内容:ASCII 模式直接输入文本;"
                "Hex 模式输入十六进制字节,例如 FF D8 FF。")
            return False
        if mode == "hex":
            try:
                pattern = bytes.fromhex(needle)
            except ValueError:
                # 非法 Hex 也要清掉上一次搜索的旧高亮,避免“提示错误但仍在高亮”。
                self._clear_search()
                self.match_label.setText("Hex 格式错误")
                self._show_search_hint(
                    "Hex 格式不正确:请输入偶数个十六进制字节,"
                    "例如 FF D8 FF 或 FFD8FF。")
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
            self._show_search_hint(
                "请输入要搜索的内容:ASCII 模式直接输入文本;"
                "Hex 模式输入十六进制字节,例如 FF D8 FF。")
            return False
        matches: list[int] = []
        start = 0
        self._search_truncated = False
        while True:
            pos = haystack.find(target, start)
            if pos < 0:
                break
            matches.append(pos)
            if len(matches) >= self.MAX_SEARCH_MATCHES:
                self._search_truncated = (
                    haystack.find(target, pos + 1) >= 0)
                break
            start = pos + 1
        self._matches = matches
        self._match_pos = -1
        self._search_key = (needle, mode, len(self._data))
        if matches:
            self.model.set_search_matches(matches, len(pattern))
            self.search_hint.hide()
            self.match_label.setText(self._match_status_text())
            if step:
                self._step(1, ensure=False)
            return True
        self.model.clear_highlights()
        self.match_label.setText("未找到")
        if mode == "hex":
            self._show_search_hint(
                "没有找到匹配的字节。可以检查:字节是否完整;"
                "是否漏掉或多了空格;试试切换 ASCII 模式搜索文本。")
        else:
            self._show_search_hint(
                "没有找到匹配的文本。可以试试:切换 Hex 模式按字节搜索;"
                "ASCII 搜索不区分大小写;确认搜索词没有多余空格;"
                "确认文件已完整载入。")
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
        self.match_label.setText(self._match_status_text())
        self.goto_offset(self._matches[self._match_pos])
        # 搜索跳转时清掉旧的字节选区,避免与新的命中位置混淆。
        self._clear_byte_selection()

    def _show_copy_menu(self, pos) -> None:
        index = self.table.indexAt(pos)
        menu = QMenu(self)
        copy_hex = menu.addAction("复制选中 HEX (Ctrl+C)")
        copy_text = menu.addAction("复制选中 ASCII 文本")
        enabled = self._copy_anchor is not None
        copy_hex.setEnabled(enabled)
        copy_text.setEnabled(enabled)
        copy_row = menu.addAction("复制当前行 HEX")
        copy_row.setEnabled(index.isValid())
        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if chosen is copy_hex:
            self._copy_selection(as_text=False)
        elif chosen is copy_text:
            self._copy_selection(as_text=True)
        elif chosen is copy_row:
            self._copy_row(index.row())

    def _copy_row(self, row: int) -> None:
        start = max(0, row) * _BYTES_PER_ROW
        if start >= len(self._data):
            return
        end = min(len(self._data), start + _BYTES_PER_ROW)
        self._copy_anchor = start
        self._copy_focus = end - 1
        self._copy_column = 1
        self.model.set_byte_selection(start, end - 1)
        self._copy_selection(as_text=False)

    def _copy_selection(self, as_text: bool | None = None) -> None:
        if (self._copy_anchor is not None and self._copy_focus is not None
                and self._copy_anchor < len(self._data)):
            start = min(self._copy_anchor, self._copy_focus)
            end = min(len(self._data), max(self._copy_anchor, self._copy_focus) + 1)
            if as_text is None:
                as_text = self._copy_column == 2
            data = self._data[start:end]
            if as_text:
                text = "".join(
                    chr(byte) if 32 <= byte <= 126 else "." for byte in data)
                kind = "ASCII"
            else:
                text = data.hex(" ")
                kind = "HEX"
            from PySide6.QtWidgets import QApplication

            QApplication.clipboard().setText(text)
            self.match_label.setText(
                f"已复制 {end - start} 字节 ({kind})")
            return

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
