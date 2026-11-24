"""文件分析页签:类型识别、文件头检测、结构解析、字符串、熵图与可编辑 Hex。"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field

from PySide6.QtCore import QObject, QRunnable, QThreadPool, QTimer, Qt, Signal
from PySide6.QtGui import QColor, QGuiApplication, QPainter
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

from core import filecarve, fileparse, fileprops
from core.analysis import digests, entropy, entropy_blocks, strings
from core.detect import detect_encodings
from core.filetype import IdentifyResult, identify
from ui import save_utils
from ui.hex_viewer import HexViewer
from ui.highlight import install_flag_highlighter, mark_item


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


@dataclass
class FileAnalysis:
    generation: int
    path: str
    result: IdentifyResult
    digest_rows: dict[str, str] = field(default_factory=dict)
    overall_entropy: float = 0.0
    entropy_blocks: list[float] = field(default_factory=list)
    image_rows: list[tuple[str, str]] = field(default_factory=list)
    detections: list = field(default_factory=list)
    nodes: list[fileparse.Node] | None = None
    parsed_supported: bool = False
    string_rows: list[tuple[int, str]] = field(default_factory=list)
    string_error: str = ""
    embedded: list[filecarve.EmbeddedFile] = field(default_factory=list)
    embedded_scanned: bool = False
    strings_capped: bool = False


def _shift_nodes(nodes: list[fileparse.Node], delta: int) -> None:
    for node in nodes:
        node.offset += delta
        _shift_nodes(node.children, delta)


def _build_analysis(data: bytes, result: IdentifyResult, generation: int,
                    path: str, pattern: str, max_strings: int,
                    cancel: threading.Event) -> FileAnalysis | None:
    analysis = FileAnalysis(generation=generation, path=path, result=result)
    analysis.digest_rows = digests(data)
    if cancel.is_set():
        return None
    analysis.overall_entropy = entropy(data)
    analysis.entropy_blocks = entropy_blocks(data)
    if cancel.is_set():
        return None

    payload = data[result.prefix:]
    analysis.image_rows = fileparse.image_info(
        result.real_name, payload,
        deep_analysis=len(payload) <= FilePanel.PNG_DEEP_ANALYSIS_LIMIT,
    )
    analysis.detections = detect_encodings(data)
    if cancel.is_set():
        return None

    parsed = fileparse.parse(result.real_name, payload)
    if parsed is not None:
        analysis.nodes, _end = parsed
        analysis.parsed_supported = True
        if result.prefix:
            _shift_nodes(analysis.nodes, result.prefix)
    if cancel.is_set():
        return None

    try:
        found = strings(
            data, min_len=4, pattern=pattern, limit=max_strings + 1)
        analysis.strings_capped = len(found) > max_strings
        analysis.string_rows = found[:max_strings]
    except Exception as exc:
        analysis.string_error = str(exc)
    if cancel.is_set():
        return None

    if len(data) <= 16 * 1024 * 1024:
        analysis.embedded = filecarve.scan_embedded(data)
        analysis.embedded_scanned = True
    return analysis


class AnalysisSignals(QObject):
    finished = Signal(object)


class AnalysisTask(QRunnable):
    def __init__(self, data: bytes, result: IdentifyResult, generation: int,
                 path: str, pattern: str, max_strings: int) -> None:
        super().__init__()
        self.data = data
        self.result = result
        self.generation = generation
        self.path = path
        self.pattern = pattern
        self.max_strings = max_strings
        self.cancel = threading.Event()
        self.signals = AnalysisSignals()

    def run(self) -> None:
        analysis = _build_analysis(
            self.data, self.result, self.generation, self.path,
            self.pattern, self.max_strings, self.cancel,
        )
        if analysis is not None:
            self.signals.finished.emit(analysis)

    def stop(self) -> None:
        self.cancel.set()


class FilePanel(QWidget):
    """文件分析页签。"""

    MAX_STRINGS = 5000
    MAX_READ_BYTES = 512 * 1024 * 1024
    SYNC_ANALYSIS_BYTES = 4 * 1024 * 1024
    PNG_DEEP_ANALYSIS_LIMIT = 16 * 1024 * 1024

    openRequested = Signal(str)
    pathChanged = Signal(str, str)

    def __init__(self) -> None:
        super().__init__()
        self._path = ""
        self._data = b""
        self._read_only = False
        self._result: IdentifyResult | None = None
        self._nodes: list[fileparse.Node] = []
        self._embedded: list[filecarve.EmbeddedFile] = []
        self._digest_rows: dict[str, str] = {}
        self._props_sections: list[fileprops.PropertySection] = []
        self._analysis_generation = 0
        self._analysis_tasks: set[AnalysisTask] = set()
        self._analysis_timer = QTimer(self)
        self._analysis_timer.setSingleShot(True)
        self._analysis_timer.setInterval(250)
        self._analysis_timer.timeout.connect(self._start_analysis)
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
        self.tabs.addTab(self._build_embedded(), "嵌套")
        self.tabs.addTab(self._build_strings(), "字符串")
        self.properties_page = self._build_properties()
        self.tabs.addTab(self.properties_page, "文件属性")
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
        self.hex_viewer.saveAsRequested.connect(self._save_as)
        self.hex_viewer.editBlocked.connect(self._on_edit_blocked)
        splitter.addWidget(self.hex_viewer)
        splitter.setSizes([300, 400])
        layout.addWidget(splitter, 1)

    def _build_overview(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.overview = QPlainTextEdit()
        self.overview.setReadOnly(True)
        self.overview.setPlaceholderText("载入文件后显示类型、哈希与检测结论")
        install_flag_highlighter(self.overview)
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

    def _build_embedded(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        bar = QHBoxLayout()
        self.btn_scan_embedded = QPushButton("扫描嵌套文件")
        self.btn_scan_embedded.clicked.connect(self._scan_embedded)
        bar.addWidget(self.btn_scan_embedded)
        self.embedded_label = QLabel("扫描内嵌的 PNG/JPEG/GIF/ZIP/PDF/ELF 等文件")
        bar.addWidget(self.embedded_label, 1)
        self.btn_extract_embedded = QPushButton("提取选中…")
        self.btn_extract_embedded.clicked.connect(self._extract_embedded)
        self.btn_extract_embedded.setEnabled(False)
        bar.addWidget(self.btn_extract_embedded)
        self.btn_extract_all_embedded = QPushButton("全部提取…")
        self.btn_extract_all_embedded.clicked.connect(self._extract_all_embedded)
        self.btn_extract_all_embedded.setEnabled(False)
        bar.addWidget(self.btn_extract_all_embedded)
        layout.addLayout(bar)

        self.embedded_table = QTableWidget(0, 4)
        self.embedded_table.setHorizontalHeaderLabels(["偏移", "类型", "大小", "说明"])
        self.embedded_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.embedded_table.verticalHeader().setVisible(False)
        self.embedded_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.embedded_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.embedded_table.cellDoubleClicked.connect(self._on_embedded_click)
        self.embedded_table.itemSelectionChanged.connect(self._update_embedded_buttons)
        layout.addWidget(self.embedded_table)
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

    def _build_properties(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        bar = QHBoxLayout()
        self.props_hint = QLabel(
            "路径、时间、Windows 属性、权限、类型和哈希；"
            "并读取系统属性处理程序提供的全部元数据"
            "（说明 / 来源 / 图像 / 照相机 / 高级照片 / GPS / 音视频等）。")
        self.props_hint.setWordWrap(True)
        bar.addWidget(self.props_hint, 1)
        self.btn_copy_props = QPushButton("复制全部属性")
        self.btn_copy_props.clicked.connect(self._copy_properties)
        bar.addWidget(self.btn_copy_props)
        self.btn_refresh_props = QPushButton("刷新")
        self.btn_refresh_props.clicked.connect(self._refresh_properties)
        bar.addWidget(self.btn_refresh_props)
        layout.addLayout(bar)

        self.props_tree = QTreeWidget()
        self.props_tree.setHeaderLabels(["属性", "值"])
        self.props_tree.setColumnWidth(0, 160)
        self.props_tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.props_tree.header().setSectionResizeMode(1, QHeaderView.Stretch)
        self.props_tree.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.props_tree.setAlternatingRowColors(True)
        layout.addWidget(self.props_tree)
        return page

    # ---------------- 载入 ----------------
    def _choose_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "选择文件")
        if path:
            self.openRequested.emit(path)

    def _confirm_discard(self) -> bool:
        """有未保存的 Hex 修改时询问,避免切换文件静默丢失。"""
        if not self.hex_viewer.is_modified:
            return True
        choice = QMessageBox.question(
            self, "CTFusion",
            "当前文件有未保存的修改。\n是否保存后再继续?",
            QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel,
            QMessageBox.Save,
        )
        if choice == QMessageBox.Cancel:
            return False
        if choice == QMessageBox.Save:
            return self._save()
        return True

    def load_file(self, path: str) -> bool:
        if not self._confirm_discard():
            return False
        try:
            size = os.path.getsize(path)
            if size > self.MAX_READ_BYTES:
                choice = QMessageBox.question(
                    self, "CTFusion",
                    f"文件大小为 {size / 1024 / 1024:.1f} MB,超过 "
                    f"{self.MAX_READ_BYTES // 1024 // 1024} MB。\n"
                    "完整载入可能占用大量内存,是否继续?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No,
                )
                if choice != QMessageBox.Yes:
                    return False
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            QMessageBox.warning(self, "CTFusion", f"读取文件失败:{e}")
            return False
        self._path = path
        self._data = data
        self._read_only = not os.access(path, os.W_OK)
        self._result = identify(data, os.path.basename(path))
        self._digest_rows = {}
        label = f"{self._path}  ({len(data):,} 字节)"
        if self._result.prefix:
            label += f"  [前置数据 {self._result.prefix} 字节]"
        if self._read_only:
            label += "  [只读]"
        self.file_label.setText(label)
        self._refresh_header()
        self._refresh_properties()
        self.hex_viewer.set_data(data, read_only=self._read_only)
        self.hex_viewer.goto_offset(0)
        if len(data) <= self.SYNC_ANALYSIS_BYTES:
            self._refresh_all()
        else:
            self._show_analysis_pending()
            self._schedule_analysis(0)
        return True

    def _refresh_all(self) -> None:
        if self._result is None:
            return
        self._analysis_timer.stop()
        self._analysis_generation += 1
        analysis = _build_analysis(
            self._data, self._result, self._analysis_generation, self._path,
            self.string_filter.text().strip(), self.MAX_STRINGS,
            threading.Event(),
        )
        if analysis is not None:
            self._apply_analysis(analysis)

    def _show_analysis_pending(self) -> None:
        self.overview.setPlainText(
            "正在后台计算哈希、熵、字符串、结构、嵌套文件和编码特征…\n"
            "文件已经可以浏览和编辑;分析完成后会自动刷新。")
        self.structure.clear()
        self.structure.addTopLevelItem(
            QTreeWidgetItem(["后台分析中…", "", "", ""]))
        self._reset_embedded()
        self.string_table.setRowCount(0)
        self.string_table.setRowCount(1)
        self.string_table.setItem(0, 0, QTableWidgetItem(""))
        self.string_table.setItem(0, 1, QTableWidgetItem("后台分析中…"))
        self.entropy_plot.set_blocks([])

    def _schedule_analysis(self, delay_ms: int = 250) -> None:
        self._analysis_generation += 1
        self._analysis_timer.start(max(0, delay_ms))

    def _start_analysis(self) -> None:
        if not self._data or self._result is None:
            return
        generation = self._analysis_generation
        task = AnalysisTask(
            self._data, self._result, generation, self._path,
            self.string_filter.text().strip(), self.MAX_STRINGS,
        )
        task.signals.finished.connect(self._on_analysis_finished)
        self._analysis_tasks.add(task)
        QThreadPool.globalInstance().start(task)

    def _on_analysis_finished(self, analysis: FileAnalysis) -> None:
        for task in list(self._analysis_tasks):
            if task.generation == analysis.generation:
                self._analysis_tasks.discard(task)
                break
        if (analysis.generation != self._analysis_generation
                or analysis.path != self._path):
            return
        self._apply_analysis(analysis)

    def _apply_analysis(self, analysis: FileAnalysis) -> None:
        self._result = analysis.result
        self._nodes = list(analysis.nodes or [])
        self._embedded = analysis.embedded
        self._digest_rows = dict(analysis.digest_rows)
        self._refresh_overview(analysis)
        self._refresh_header()
        self._refresh_properties()
        self._populate_structure(analysis)
        self._populate_embedded(analysis.embedded, analysis.embedded_scanned)
        self._populate_strings(analysis.string_rows, analysis.string_error)
        self.entropy_plot.set_blocks(analysis.entropy_blocks)

    # ---------------- 各视图刷新 ----------------
    def _refresh_overview(self, analysis: FileAnalysis) -> None:
        result = analysis.result
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
        for name, value in analysis.digest_rows.items():
            lines.append(f"{name:<10}: {value}")
        lines.append(
            f"整体熵     : {analysis.overall_entropy:.4f} bit/byte  (0~8)")

        if analysis.image_rows:
            lines.append("")
            lines.append("── 图像信息 ──")
            lines.extend(
                f"{key:<10}: {value}" for key, value in analysis.image_rows)

        if analysis.detections:
            lines.append("")
            lines.append("── 编码特征 ──")
            for item in analysis.detections[:10]:
                preview = item.decoded[:80].replace("\n", " ")
                lines.append(
                    f"[{item.kind}] @ 0x{item.offset:X}  {item.text[:60]}"
                    + (f"  ->  {preview}" if preview else ""))
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
        if result.prefix:
            rows.append(("前置数据", f"{result.prefix} 字节(magic 之前)"))
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

    def _refresh_properties(self) -> None:
        if not hasattr(self, "props_tree"):
            return
        self.props_tree.clear()
        self._props_sections = []
        if not self._path:
            self.props_hint.setText("载入文件后显示完整属性。")
            return
        try:
            sections = fileprops.collect(
                self._path,
                data=self._data,
                result=self._result,
                digest_rows=self._digest_rows or None,
                compute_hashes=False,
            )
        except OSError as exc:
            self.props_hint.setText(str(exc))
            return
        self._props_sections = sections
        self.props_hint.setText(
            "路径、时间、Windows 属性、权限、类型和哈希；"
            "并读取系统属性处理程序提供的全部元数据"
            "（说明 / 来源 / 图像 / 照相机 / 高级照片 / GPS / 音视频等）。")
        for section in sections:
            top = QTreeWidgetItem([section.title, ""])
            font = top.font(0)
            font.setBold(True)
            top.setFont(0, font)
            self.props_tree.addTopLevelItem(top)
            for key, value in section.rows:
                child = QTreeWidgetItem([key, value])
                child.setToolTip(1, value)
                top.addChild(child)
            top.setExpanded(True)

    def _copy_properties(self) -> None:
        if not self._props_sections:
            QMessageBox.information(self, "CTFusion", "当前没有可复制的文件属性。")
            return
        QGuiApplication.clipboard().setText(
            fileprops.sections_to_text(self._props_sections))
        self.btn_copy_props.setText("已复制 ✓")
        QTimer.singleShot(
            1200, lambda: self.btn_copy_props.setText("复制全部属性"))

    def show_properties(self) -> None:
        self._refresh_properties()
        index = self.tabs.indexOf(self.properties_page)
        if index >= 0:
            self.tabs.setCurrentIndex(index)

    def _populate_structure(self, analysis: FileAnalysis) -> None:
        self.structure.clear()
        if not analysis.parsed_supported or analysis.nodes is None:
            root = QTreeWidgetItem(
                ["该格式暂未支持结构解析", "", "",
                 "已支持:PNG / JPG / GIF / BMP / ZIP"])
            self.structure.addTopLevelItem(root)
            return
        for node in analysis.nodes:
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

    def _populate_strings(
            self, found: list[tuple[int, str]], error: str = "") -> None:
        self.string_table.setRowCount(0)
        if error:
            self.string_table.setRowCount(1)
            self.string_table.setItem(0, 0, QTableWidgetItem(""))
            self.string_table.setItem(
                0, 1, QTableWidgetItem(f"字符串扫描错误:{error}"))
            return
        if not found:
            self.string_table.setRowCount(1)
            self.string_table.setItem(0, 0, QTableWidgetItem("提示"))
            if self.string_filter.text().strip():
                message = (
                    "没有找到匹配的字符串。可以试试:缩短关键字;"
                    "去掉正则特殊字符;或清空过滤框查看全部字符串。")
            else:
                message = (
                    "未提取到可打印字符串。该文件可能是压缩/加密数据,"
                    "或字符串长度都低于当前最小长度。")
            self.string_table.setItem(0, 1, QTableWidgetItem(message))
            return
        self.string_table.setRowCount(len(found))
        for row, (offset, text) in enumerate(found):
            item_off = QTableWidgetItem(f"0x{offset:X}")
            item_off.setData(Qt.UserRole, offset)
            self.string_table.setItem(row, 0, item_off)
            item_text = QTableWidgetItem(text[:200])
            mark_item(item_text)
            self.string_table.setItem(row, 1, item_text)

    def _refresh_strings(self) -> None:
        if not self._data:
            return
        if len(self._data) <= self.SYNC_ANALYSIS_BYTES:
            self._refresh_all()
        else:
            self._show_analysis_pending()
            self._schedule_analysis(0)

    # ---------------- 编辑 / 保存 ----------------
    def _on_data_edited(self) -> None:
        if not self._path:
            return
        self._data = self.hex_viewer.data_bytes
        self._result = identify(self._data, os.path.basename(self._path))
        self._digest_rows = {}
        self._refresh_header()
        self._refresh_properties()
        self.file_label.setText(f"{self._path}  ({len(self._data):,} 字节)  [已修改]")
        if len(self._data) <= self.SYNC_ANALYSIS_BYTES:
            self._refresh_all()
        else:
            self._show_analysis_pending()
            self._schedule_analysis()

    def _on_edit_blocked(self) -> None:
        QMessageBox.warning(
            self, "CTFusion",
            "当前文件是只读的,不能修改。\n"
            "请使用「保存副本…」把修改结果保存到新文件。")

    def _save(self) -> bool:
        if not self._path:
            return False
        if self._read_only:
            QMessageBox.warning(
                self, "CTFusion",
                "当前文件是只读的,不能覆盖保存。\n请使用「另存为…」保存副本。")
            return False
        if self.hex_viewer.save_to(self._path):
            self.file_label.setText(f"{self._path}  ({len(self._data):,} 字节)  [已保存]")
            return True
        return False

    def _save_as(self) -> None:
        if not self._data:
            self.overview.setPlainText("当前没有已载入的文件，无法另存为。")
            return
        default = self._path or "output.bin"
        path, _ = QFileDialog.getSaveFileName(self, "另存为", default)
        if not path:
            return
        if not self.hex_viewer.save_to(path):
            return
        old_path = self._path
        # 另存为之后后续 Ctrl+S 应写新文件,而不是旧路径。
        self._path = path
        self._read_only = not os.access(path, os.W_OK)
        self._result = identify(self._data, os.path.basename(path))
        self._digest_rows = {}
        label = f"{path}  ({len(self._data):,} 字节)"
        if self._read_only:
            label += "  [只读]"
        self.file_label.setText(label)
        self.hex_viewer.set_data(
            self._data, read_only=self._read_only, preserve_search=True)
        self._refresh_header()
        self._refresh_properties()
        if len(self._data) <= self.SYNC_ANALYSIS_BYTES:
            self._refresh_all()
        else:
            self._show_analysis_pending()
            self._schedule_analysis(0)
        self.pathChanged.emit(old_path, path)

    # ---------------- 联动 ----------------
    def _on_structure_click(self, item: QTreeWidgetItem, _column: int) -> None:
        offset = item.data(0, Qt.UserRole)
        if offset is not None:
            self.hex_viewer.goto_offset(int(offset))

    def _on_string_click(self, row: int, _column: int) -> None:
        item = self.string_table.item(row, 0)
        offset = item.data(Qt.UserRole) if item is not None else None
        if offset is not None:
            self.hex_viewer.goto_offset(int(offset))

    # ---------------- 文件嵌套 ----------------
    def _reset_embedded(self) -> None:
        self._embedded = []
        self.embedded_table.setRowCount(0)
        self.embedded_label.setText(
            "扫描内嵌的 PNG/JPEG/GIF/ZIP/PDF/ELF 等文件；点击“扫描嵌套文件”开始")
        self.btn_extract_embedded.setEnabled(False)
        self.btn_extract_all_embedded.setEnabled(False)

    def _populate_embedded(self, items: list[filecarve.EmbeddedFile],
                           scanned: bool) -> None:
        self._embedded = items
        self.embedded_table.setRowCount(len(items))
        for row, item in enumerate(items):
            values = [
                f"0x{item.offset:X}",
                item.kind,
                f"{item.size:,}" if item.known_size else "?",
                item.detail,
            ]
            for col, value in enumerate(values):
                cell = QTableWidgetItem(value)
                if col == 3:
                    mark_item(cell)
                self.embedded_table.setItem(row, col, cell)
        suffix = "(仅扫描前 64MB)" if len(self._data) > 64 * 1024 * 1024 else ""
        if items:
            self.embedded_label.setText(
                f"发现 {len(items)} 个内嵌文件{suffix};双击跳转,可单选或全部提取。")
        elif scanned:
            self.embedded_label.setText(
                f"未发现可识别的内嵌文件(已扫描常见强 magic){suffix}。")
        else:
            self.embedded_label.setText(
                "大文件未自动扫描;点击「扫描嵌套文件」开始。")
        self.btn_extract_embedded.setEnabled(bool(items))
        self.btn_extract_all_embedded.setEnabled(bool(items))

    def _scan_embedded(self) -> None:
        if not self._data:
            return
        items = filecarve.scan_embedded(self._data)
        self._populate_embedded(items, True)

    def _update_embedded_buttons(self) -> None:
        has_selection = self.embedded_table.currentRow() >= 0
        self.btn_extract_embedded.setEnabled(has_selection)

    def _on_embedded_click(self, row: int, _column: int) -> None:
        if 0 <= row < len(self._embedded):
            self.hex_viewer.goto_offset(self._embedded[row].offset)

    def _extract_embedded(self) -> None:
        row = self.embedded_table.currentRow()
        if not 0 <= row < len(self._embedded):
            return
        item = self._embedded[row]
        default = filecarve.suggested_name(item, row)
        path, _ = QFileDialog.getSaveFileName(self, "保存内嵌文件", default)
        if not path:
            return
        if not save_utils.write_bytes(
                self, filecarve.extract(self._data, item), path):
            return
        QMessageBox.information(self, "CTFusion", f"已提取 {item.kind}:\n{path}")

    def _extract_all_embedded(self) -> None:
        if not self._embedded:
            return
        target = QFileDialog.getExistingDirectory(self, "选择提取目录")
        if not target:
            return
        pending: list[tuple[str, bytes]] = []
        for row, item in enumerate(self._embedded):
            name = filecarve.safe_name(filecarve.suggested_name(item, row))
            pending.append(
                (os.path.join(target, name), filecarve.extract(self._data, item)))
        count = save_utils.write_many(self, pending)
        QMessageBox.information(self, "CTFusion", f"已提取 {count} 个内嵌文件到:\n{target}")

    def shutdown(self, timeout_ms: int = 5_000) -> bool:
        self._analysis_timer.stop()
        self._analysis_generation += 1
        for task in self._analysis_tasks:
            task.stop()
        done = QThreadPool.globalInstance().waitForDone(timeout_ms)
        if done:
            self._analysis_tasks.clear()
        return done

    def clear(self) -> None:
        self._analysis_timer.stop()
        self._analysis_generation += 1
        self._path = ""
        self._data = b""
        self._read_only = False
        self._result = None
        self._nodes = []
        self._embedded = []
        self._digest_rows = {}
        self._props_sections = []
        self.file_label.setText("拖入任意文件开始分析")
        self.overview.clear()
        self.header_table.setRowCount(0)
        self.structure.clear()
        self.string_table.setRowCount(0)
        self.embedded_table.setRowCount(0)
        if hasattr(self, "props_tree"):
            self.props_tree.clear()
            self.props_hint.setText("载入文件后显示完整属性。")
        self.embedded_label.setText(
            "扫描内嵌的 PNG/JPEG/GIF/ZIP/PDF/ELF 等文件")
        self.entropy_plot.set_blocks([])
        self.hex_viewer.clear()
        self.btn_extract_embedded.setEnabled(False)
        self.btn_extract_all_embedded.setEnabled(False)
