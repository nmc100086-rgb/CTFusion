"""文件分析页签:类型识别、文件头检测、结构解析、字符串、熵图与可编辑 Hex。"""

from __future__ import annotations

import os

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import fileparse
from core.analysis import digests, entropy, entropy_blocks, strings
from core.filetype import IdentifyResult, identify
from ui.hex_viewer import HexViewer


class EntropyPlot(QWidget):
    """熵图:每根柱是一个数据块的香农熵(绿=低,红=接近随机)。"""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._blocks: list[float] = []
        self.setMinimumHeight(120)
        self.setMinimumWidth(160)

    def set_blocks(self, blocks: list[float]) -> None:
        self._blocks = blocks
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor("#1b1b1b"))
        if not self._blocks:
            painter.setPen(QColor("#888888"))
            painter.drawText(self.rect(), Qt.AlignCenter, "无数据")
            return
        width = self.width()
        height = self.height() - 16
        bar_w = width / len(self._blocks)
        for i, value in enumerate(self._blocks):
            ratio = max(0.0, min(1.0, value / 8.0))
            color = QColor.fromHsv(int((1.0 - ratio) * 120), 210, 235)
            painter.fillRect(
                int(i * bar_w), int(height * (1 - ratio)),
                max(1, int(bar_w)), max(1, int(height * ratio)), color,
            )
        painter.setPen(QColor("#cccccc"))
        painter.drawText(4, self.height() - 3,
                         f"{len(self._blocks)} 块 | 均值 {sum(self._blocks) / len(self._blocks):.2f} bit/byte")


class FilePanel(QWidget):
    """文件分析页签。"""

    MAX_STRINGS = 5000

    def __init__(self) -> None:
        super().__init__()
        self._path = ""
        self._data = b""
        self._result: IdentifyResult | None = None
        self._nodes: list[fileparse.Node] = []
        self._build_ui()

    # ---------------- UI ----------------
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        bar = QHBoxLayout()
        self.btn_open = QPushButton("打开文件…")
        self.btn_open.clicked.connect(self._choose_file)
        bar.addWidget(self.btn_open)
        self.file_label = QLabel("拖入任意文件开始分析")
        bar.addWidget(self.file_label, 1)
        self.btn_save_as = QPushButton("另存为…")
        self.btn_save_as.clicked.connect(self._save_as)
        bar.addWidget(self.btn_save_as)
        layout.addLayout(bar)

        splitter = QSplitter(Qt.Vertical)
        splitter.setChildrenCollapsible(False)

        top = QSplitter(Qt.Horizontal)
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_overview(), "概览")
        self.tabs.addTab(self._build_header(), "文件头")
        self.tabs.addTab(self._build_structure(), "结构")
        self.tabs.addTab(self._build_strings(), "字符串")
        top.addWidget(self.tabs)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.addWidget(QLabel("熵图(越高越接近加密/压缩)"))
        self.entropy_plot = EntropyPlot()
        right_layout.addWidget(self.entropy_plot, 1)
        top.addWidget(right)
        top.setSizes([700, 260])

        splitter.addWidget(top)
        self.hex_viewer = HexViewer()
        self.hex_viewer.dataEdited.connect(self._on_data_edited)
        self.hex_viewer.saveRequested.connect(self._save)
        splitter.addWidget(self.hex_viewer)
        splitter.setSizes([300, 400])
        layout.addWidget(splitter, 1)

    def _build_overview(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.overview = QPlainTextEdit()
        self.overview.setReadOnly(True)
        self.overview.setPlaceholderText("载入文件后显示类型、哈希与检测结论")
        layout.addWidget(self.overview)
        return page

    def _build_header(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.header_table = QTableWidget(0, 2)
        self.header_table.setHorizontalHeaderLabels(["检查项", "结果"])
        self.header_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.header_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.header_table.verticalHeader().setVisible(False)
        self.header_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.header_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        layout.addWidget(self.header_table)
        return page

    def _build_structure(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.structure = QTreeWidget()
        self.structure.setHeaderLabels(["结构", "偏移", "长度", "说明"])
        self.structure.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.structure.header().setSectionResizeMode(3, QHeaderView.Stretch)
        self.structure.itemDoubleClicked.connect(self._on_structure_click)
        layout.addWidget(self.structure)
        return page

    def _build_strings(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("过滤(正则):"))
        self.string_filter = QLineEdit()
        self.string_filter.setPlaceholderText("如 flag|ctf")
        self.string_filter.returnPressed.connect(self._refresh_strings)
        bar.addWidget(self.string_filter, 1)
        layout.addLayout(bar)

        self.string_table = QTableWidget(0, 2)
        self.string_table.setHorizontalHeaderLabels(["偏移", "字符串"])
        self.string_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.string_table.verticalHeader().setVisible(False)
        self.string_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.string_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.string_table.cellDoubleClicked.connect(self._on_string_click)
        layout.addWidget(self.string_table)
        return page

    # ---------------- 载入 ----------------
    def _choose_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "选择文件")
        if path:
            self.load_file(path)

    def load_file(self, path: str) -> None:
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            QMessageBox.warning(self, "MiscKit", f"读取文件失败:{e}")
            return
        self._path = path
        self._data = data
        self._result = identify(data, os.path.basename(path))
        self.file_label.setText(f"{self._path}  ({len(data):,} 字节)")
        self._refresh_all()

    def _refresh_all(self) -> None:
        self._refresh_overview()
        self._refresh_header()
        self._refresh_structure()
        self._refresh_strings()
        self.entropy_plot.set_blocks(entropy_blocks(self._data))
        self.hex_viewer.set_data(self._data)
        self.hex_viewer.goto_offset(0)

    # ---------------- 各视图刷新 ----------------
    def _refresh_overview(self) -> None:
        result = self._result
        if result is None:
            return
        lines = [
            f"文件名     : {result.filename}",
            f"文件大小   : {result.size:,} 字节",
            f"声明扩展名 : {result.declared_ext or '(无)'}",
            f"真实类型   : {result.real_name}" + (f"  (建议扩展名 {result.real_ext})" if result.real_ext else ""),
            f"扩展名匹配 : {'是' if result.ext_ok else '否 ⚠'}",
            "",
            "── 哈希 ──",
        ]
        for name, value in digests(self._data).items():
            lines.append(f"{name:<10}: {value}")
        lines.append(f"整体熵     : {entropy(self._data):.4f} bit/byte  (0~8)")

        info_rows = fileparse.image_info(result.real_name, self._data)
        if info_rows:
            lines.append("")
            lines.append("── 图像信息 ──")
            lines.extend(f"{key:<10}: {value}" for key, value in info_rows)

        if result.trailing:
            t = result.trailing
            lines.append("")
            lines.append("── 尾随数据 ──")
            lines.append(f"逻辑结束   : {t.offset:,}")
            lines.append(f"附加长度   : {t.length:,} 字节")
            if t.hint:
                lines.append(f"内容提示   : {t.hint}")
        if result.matches:
            lines.append("")
            lines.append("── 全部命中签名 ──")
            lines.append("、".join(result.matches))
        if result.notes:
            lines.append("")
            lines.append("── 检测结论 ──")
            lines.extend(f"• {note}" for note in result.notes)
        self.overview.setPlainText("\n".join(lines))

    def _refresh_header(self) -> None:
        result = self._result
        self.header_table.setRowCount(0)
        if result is None:
            return
        head = self._data[:16]
        head_ascii = "".join(chr(b) if 32 <= b <= 126 else "." for b in head)
        rows: list[tuple[str, str]] = [
            ("实际文件头", f"{' '.join(f'{b:02X}' for b in head)}  |  {head_ascii}"),
        ]
        check = result.header
        if check is not None and check.expected:
            rows.append(("期望 magic", check.expected_hex))
            rows.append(("magic 偏移", f"0x{check.offset:X} ({check.offset})"))
            rows.append(("文件头匹配", "是 ✓" if check.matched else "否 ⚠"))
        else:
            rows.append(("期望 magic", "未知(未命中内置签名)"))
            rows.append(("文件头匹配", "无法判定"))
        rows.extend([
            ("真实类型", result.real_name),
            ("声明扩展名", result.declared_ext or "(无)"),
            ("建议扩展名", result.real_ext or "(未知)"),
            ("扩展名匹配", "是" if result.ext_ok else "否 ⚠"),
        ])
        if result.matches:
            rows.append(("全部命中签名", "、".join(result.matches)))
        if result.trailing:
            t = result.trailing
            rows.append(("尾随数据", f"逻辑结束 0x{t.offset:X},附加 {t.length:,} 字节 {t.hint}".strip()))
        else:
            rows.append(("尾随数据", "无"))
        rows.append(("文件大小", f"{result.size:,} 字节"))

        self.header_table.setRowCount(len(rows))
        for row, (key, value) in enumerate(rows):
            self.header_table.setItem(row, 0, QTableWidgetItem(key))
            self.header_table.setItem(row, 1, QTableWidgetItem(value))

    def _refresh_structure(self) -> None:
        self.structure.clear()
        self._nodes = []
        if self._result is None:
            return
        parsed = fileparse.parse(self._result.real_name, self._data)
        if parsed is None:
            root = QTreeWidgetItem(["该格式暂未支持结构解析", "", "", "已支持:PNG / JPG / GIF / BMP / ZIP"])
            self.structure.addTopLevelItem(root)
            return
        nodes, _end = parsed
        self._nodes = nodes
        for node in nodes:
            self._add_node(None, node)

    def _add_node(self, parent: QTreeWidgetItem | None, node: fileparse.Node) -> None:
        item = QTreeWidgetItem([node.title, f"0x{node.offset:X}", f"{node.size:,}", node.detail])
        item.setData(0, Qt.UserRole, node.offset)
        if parent is None:
            self.structure.addTopLevelItem(item)
        else:
            parent.addChild(item)
        for child in node.children:
            self._add_node(item, child)

    def _refresh_strings(self) -> None:
        self.string_table.setRowCount(0)
        if not self._data:
            return
        pattern = self.string_filter.text().strip()
        try:
            found = strings(self._data, min_len=4, pattern=pattern)
        except Exception as e:  # 正则语法错误
            self.string_table.setRowCount(1)
            self.string_table.setItem(0, 0, QTableWidgetItem(""))
            self.string_table.setItem(0, 1, QTableWidgetItem(f"正则错误:{e}"))
            return
        found = found[:self.MAX_STRINGS]
        self.string_table.setRowCount(len(found))
        for row, (offset, text) in enumerate(found):
            item_off = QTableWidgetItem(f"0x{offset:X}")
            item_off.setData(Qt.UserRole, offset)
            self.string_table.setItem(row, 0, item_off)
            self.string_table.setItem(row, 1, QTableWidgetItem(text[:200]))

    # ---------------- 编辑 / 保存 ----------------
    def _on_data_edited(self) -> None:
        if not self._path:
            return
        self._data = self.hex_viewer.data_bytes
        self._result = identify(self._data, os.path.basename(self._path))
        self._refresh_overview()
        self._refresh_header()
        self._refresh_structure()
        self._refresh_strings()
        self.entropy_plot.set_blocks(entropy_blocks(self._data))
        self.file_label.setText(f"{self._path}  ({len(self._data):,} 字节)  [已修改]")

    def _save(self) -> None:
        if not self._path:
            return
        if self.hex_viewer.save_to(self._path):
            self.file_label.setText(f"{self._path}  ({len(self._data):,} 字节)  [已保存]")

    def _save_as(self) -> None:
        if not self._data:
            return
        default = self._path or "output.bin"
        path, _ = QFileDialog.getSaveFileName(self, "另存为", default)
        if not path:
            return
        if self.hex_viewer.save_to(path):
            self.file_label.setText(f"{path}  ({len(self._data):,} 字节)")

    # ---------------- 联动 ----------------
    def _on_structure_click(self, item: QTreeWidgetItem, _column: int) -> None:
        offset = item.data(0, Qt.UserRole)
        if offset is not None:
            self.hex_viewer.goto_offset(int(offset))

    def _on_string_click(self, row: int, _column: int) -> None:
        item = self.string_table.item(row, 0)
        if item is not None:
            self.hex_viewer.goto_offset(int(item.data(Qt.UserRole)))
