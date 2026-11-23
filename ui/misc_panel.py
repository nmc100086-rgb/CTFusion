"""杂项工具页签：二维码识别、乱码修复、Base64/Hex 与文件互转。

这些功能不依赖 ZIP、图片隐写等具体页签，集中放在一个工具箱里，避免
和“编码解码”页的纯文本 Base64/Hex 算法重复：
- 编码解码页：文本 <-> Base64/Hex
- 这里：Base64/Hex 字节 <-> 图片 / ZIP / 任意文件
"""

from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import QBuffer, QIODevice, Qt, Signal
from PySide6.QtGui import QGuiApplication, QImage, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core import datatools, mojibake, qrcode
from ui import i18n, save_utils
from ui.highlight import install_flag_highlighter
from ui.save_utils import save_bytes_dialog

_IMAGE_FILTER = (
    "图片 (*.png *.jpg *.jpeg *.gif *.bmp *.webp *.tif *.tiff *.ico);;"
    "所有文件 (*.*)"
)


def _set_status(label: QLabel, text: str, kind: str = "info") -> None:
    colors = {
        "info": "#8ab4f8",
        "ok": "#7ec699",
        "warn": "#e2b341",
        "error": "#e06c75",
    }
    label.setStyleSheet(f"color:{colors.get(kind, colors['info'])};")
    label.setText(text)


def _scaled(image: QImage, label: QLabel) -> QPixmap:
    pixmap = QPixmap.fromImage(image)
    size = label.size()
    if size.width() > 24 and size.height() > 24:
        pixmap = pixmap.scaled(
            size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
    return pixmap


def _qimage_png_bytes(image: QImage) -> bytes:
    buffer = QBuffer()
    buffer.open(QIODevice.WriteOnly)
    if not image.save(buffer, "PNG"):
        raise ValueError("剪贴板图片无法转换为 PNG")
    return bytes(buffer.data())


class QrScanTab(QWidget):
    """二维码 / 条码识别，结果可复制。"""

    def __init__(self) -> None:
        super().__init__()
        self._image_data = b""
        self._image: QImage | None = None
        self._results: list[qrcode.BarcodeResult] = []
        self.setAcceptDrops(True)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        bar = QHBoxLayout()
        self.btn_open = QPushButton("打开图片…")
        self.btn_open.clicked.connect(self._choose_file)
        bar.addWidget(self.btn_open)
        self.btn_clipboard = QPushButton("从剪贴板读取")
        self.btn_clipboard.clicked.connect(self._from_clipboard)
        bar.addWidget(self.btn_clipboard)
        self.btn_scan = QPushButton("重新识别")
        self.btn_scan.clicked.connect(self._scan)
        bar.addWidget(self.btn_scan)
        self.btn_clear = QPushButton("清空")
        self.btn_clear.clicked.connect(self.clear)
        bar.addWidget(self.btn_clear)
        bar.addStretch()
        self.status = QLabel("支持二维码、Micro QR、Data Matrix、Aztec、PDF417 和常见一维条码。")
        self.status.setWordWrap(True)
        bar.addWidget(self.status, 2)
        layout.addLayout(bar)

        splitter = QSplitter(Qt.Horizontal)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        self.preview = QLabel("拖入图片，或点击「打开图片…」\n也可以直接从剪贴板读取截图")
        self.preview.setAlignment(Qt.AlignCenter)
        self.preview.setMinimumSize(260, 240)
        self.preview.setStyleSheet("background:#1b1b1b;color:#888;")
        left_layout.addWidget(self.preview, 1)
        self.image_info = QLabel("")
        self.image_info.setWordWrap(True)
        left_layout.addWidget(self.image_info)
        splitter.addWidget(left)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["格式", "内容预览", "纠错", "方向"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.itemSelectionChanged.connect(self._on_selection)
        right_layout.addWidget(self.table, 1)

        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setPlaceholderText("识别结果会显示在这里；可直接选中复制。")
        install_flag_highlighter(self.detail)
        right_layout.addWidget(self.detail, 1)

        actions = QHBoxLayout()
        self.btn_copy = QPushButton("复制选中结果")
        self.btn_copy.clicked.connect(self._copy_selected)
        actions.addWidget(self.btn_copy)
        self.btn_copy_hex = QPushButton("复制原始字节 Hex")
        self.btn_copy_hex.clicked.connect(self._copy_raw_hex)
        actions.addWidget(self.btn_copy_hex)
        self.btn_copy_all = QPushButton("复制全部结果")
        self.btn_copy_all.clicked.connect(self._copy_all)
        actions.addWidget(self.btn_copy_all)
        actions.addStretch()
        right_layout.addLayout(actions)
        splitter.addWidget(right)
        splitter.setSizes([330, 690])
        layout.addWidget(splitter, 1)

    # ---- 载入 ----
    def _choose_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择二维码 / 条码图片", "", _IMAGE_FILTER)
        if path:
            self.load_file(path)

    def load_file(self, path: str) -> bool:
        try:
            data = Path(path).read_bytes()
        except OSError as exc:
            _set_status(self.status, f"读取图片失败:{exc}", "error")
            return False
        if len(data) > qrcode.MAX_IMAGE_BYTES:
            _set_status(
                self.status,
                f"图片文件过大({len(data) / 1024 / 1024:.1f} MB)，"
                f"上限 {qrcode.MAX_IMAGE_BYTES // 1024 // 1024} MB",
                "error")
            return False
        image = QImage.fromData(data)
        if image.isNull():
            _set_status(self.status, "无法解码该图片，请确认格式是否受支持。", "error")
            return False
        self._image_data = data
        self._image = image
        self.preview.setPixmap(_scaled(image, self.preview))
        self.image_info.setText(
            f"{path}\n{image.width()} × {image.height()} 像素，"
            f"{len(data):,} 字节")
        self.table.setRowCount(0)
        self.detail.clear()
        self._results = []
        _set_status(self.status, "图片已载入，正在识别…", "info")
        self._scan()
        return True

    def _from_clipboard(self) -> None:
        image = QGuiApplication.clipboard().image()
        if image.isNull():
            _set_status(self.status, "剪贴板中没有图片。请先截图或复制一张图片。", "warn")
            return
        try:
            data = _qimage_png_bytes(image)
        except ValueError as exc:
            _set_status(self.status, str(exc), "error")
            return
        self._image_data = data
        self._image = image
        self.preview.setPixmap(_scaled(image, self.preview))
        self.image_info.setText(
            f"剪贴板图片 {image.width()} × {image.height()} 像素，"
            f"{len(data):,} 字节")
        self.table.setRowCount(0)
        self.detail.clear()
        self._results = []
        _set_status(self.status, "已读取剪贴板图片，正在识别…", "info")
        self._scan()

    def _scan(self) -> None:
        if not self._image_data:
            _set_status(self.status, "请先打开图片或从剪贴板读取。", "warn")
            return
        try:
            results = qrcode.scan_image_bytes(self._image_data)
        except qrcode.QrError as exc:
            self._results = []
            self.table.setRowCount(0)
            self.detail.clear()
            _set_status(self.status, str(exc), "error")
            return
        self._results = results
        self._populate(results)
        if not results:
            _set_status(
                self.status,
                "没有发现二维码/条码。可以试试：放大图片、提高对比度、"
                "换一张原图，或确认不是被裁剪/遮挡的码。",
                "warn")
            return
        _set_status(
            self.status,
            f"识别到 {len(results)} 个结果。选中表格行后复制；"
            "多行内容可在下方直接选中。",
            "ok")

    def _populate(self, results: list[qrcode.BarcodeResult]) -> None:
        self.table.setRowCount(len(results))
        for row, result in enumerate(results):
            preview = result.text.replace("\n", " ⏎ ").replace("\r", "")
            if len(preview) > 120:
                preview = preview[:120] + "…"
            values = [
                result.format,
                preview or f"(二进制 {len(result.raw)} 字节)",
                result.ec_level or "—",
                str(result.orientation) if result.orientation else "—",
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.UserRole, row)
                self.table.setItem(row, column, item)
        if results:
            self.table.selectRow(0)

    def _selected(self) -> qrcode.BarcodeResult | None:
        row = self.table.currentRow()
        if 0 <= row < len(self._results):
            return self._results[row]
        return None

    def _on_selection(self) -> None:
        result = self._selected()
        if result is None:
            self.detail.clear()
            return
        parts: list[str] = []
        parts.append(result.text if result.text else "(该条码没有文本内容，请复制原始字节)")
        parts.append("")
        parts.append("─" * 46)
        parts.append(f"格式      : {result.format}")
        parts.append(f"内容类型  : {result.content_type or '—'}")
        parts.append(f"纠错级别  : {result.ec_level or '—'}")
        parts.append(f"方向      : {result.orientation}")
        parts.append(f"位置      : {result.position or '—'}")
        parts.append(f"原始字节  : {len(result.raw):,} 字节")
        if result.raw:
            shown = result.raw[:4096]
            suffix = "\n…（仅显示前 4096 字节，复制时使用完整数据）" if len(result.raw) > 4096 else ""
            parts.append("")
            parts.append("原始 Hex :")
            parts.append(shown.hex(" ").upper() + suffix)
        self.detail.setPlainText("\n".join(parts))

    def _copy_selected(self) -> None:
        result = self._selected()
        if result is None:
            _set_status(self.status, "请先选中一条识别结果。", "warn")
            return
        if not result.text:
            _set_status(self.status, "该结果没有文本，请使用「复制原始字节 Hex」。", "warn")
            return
        QGuiApplication.clipboard().setText(result.text)
        self.btn_copy.setText("已复制 ✓")
        from PySide6.QtCore import QTimer
        QTimer.singleShot(1200, lambda: self.btn_copy.setText("复制选中结果"))
        _set_status(self.status, f"已复制 {len(result.text):,} 个字符。", "ok")

    def _copy_raw_hex(self) -> None:
        result = self._selected()
        if result is None:
            _set_status(self.status, "请先选中一条识别结果。", "warn")
            return
        if not result.raw:
            _set_status(self.status, "该结果没有原始字节。", "warn")
            return
        QGuiApplication.clipboard().setText(result.raw_hex)
        self.btn_copy_hex.setText("已复制 ✓")
        from PySide6.QtCore import QTimer
        QTimer.singleShot(1200, lambda: self.btn_copy_hex.setText("复制原始字节 Hex"))
        _set_status(self.status, f"已复制 {len(result.raw):,} 字节的 Hex。", "ok")

    def _copy_all(self) -> None:
        if not self._results:
            _set_status(self.status, "当前没有识别结果。", "warn")
            return
        chunks = []
        for index, result in enumerate(self._results, 1):
            content = result.text or f"(二进制) {result.raw_hex}"
            chunks.append(f"[{index}] {result.format}\n{content}")
        QGuiApplication.clipboard().setText("\n\n".join(chunks))
        _set_status(self.status, f"已复制 {len(self._results)} 条结果。", "ok")

    def clear(self) -> None:
        self._image_data = b""
        self._image = None
        self._results = []
        self.preview.setPixmap(QPixmap())
        self.preview.setText("拖入图片，或点击「打开图片…」\n也可以直接从剪贴板读取截图")
        self.image_info.setText("")
        self.table.setRowCount(0)
        self.detail.clear()
        _set_status(self.status, "已清空。", "info")

    # ---- 拖放 ----
    def dragEnterEvent(self, event) -> None:  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:  # noqa: N802
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if path and os.path.isfile(path):
                self.load_file(path)
                event.acceptProposedAction()
                return


class MojibakeTab(QWidget):
    """乱码自动修复 + 手动编码转换。"""

    def __init__(self) -> None:
        super().__init__()
        self._candidates: list[mojibake.RepairCandidate] = []
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        bar = QHBoxLayout()
        bar.addWidget(QLabel("输入格式:"))
        self.input_mode = QComboBox()
        self.input_mode.addItem("文本", "text")
        self.input_mode.addItem("Hex 字节", "hex")
        bar.addWidget(self.input_mode)
        self.btn_auto = QPushButton("自动分析乱码")
        self.btn_auto.clicked.connect(self._auto_analyze)
        bar.addWidget(self.btn_auto)
        self.btn_clear = QPushButton("清空")
        self.btn_clear.clicked.connect(self._clear)
        bar.addWidget(self.btn_clear)
        bar.addStretch()
        self.status = QLabel(
            "自动枚举 UTF-8 / GB18030 / Big5 / Latin-1 / CP1252 的错误解释组合；"
            "候选按可读性排序，双击填入结果。")
        self.status.setWordWrap(True)
        bar.addWidget(self.status, 2)
        layout.addLayout(bar)

        splitter = QSplitter(Qt.Vertical)
        self.input_edit = QPlainTextEdit()
        self.input_edit.setPlaceholderText(
            "粘贴乱码，例如：æµ‹è¯• / 娴嬭瘯 / ÄãºÃ£¬ÊÀ½ç\n"
            "输入格式选「Hex 字节」时，粘贴 c4e3bac3 这类连续 Hex。")
        splitter.addWidget(self.input_edit)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["修复方式", "结果预览", "评分"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.cellDoubleClicked.connect(self._apply_row)
        splitter.addWidget(self.table)

        output_widget = QWidget()
        output_layout = QVBoxLayout(output_widget)
        output_layout.setContentsMargins(0, 0, 0, 0)
        out_head = QHBoxLayout()
        out_head.addWidget(QLabel("修复结果:"))
        out_head.addStretch()
        self.btn_copy = QPushButton("复制结果")
        self.btn_copy.clicked.connect(self._copy)
        out_head.addWidget(self.btn_copy)
        output_layout.addLayout(out_head)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlaceholderText("自动分析或手动转换后显示结果")
        install_flag_highlighter(self.output)
        output_layout.addWidget(self.output)
        splitter.addWidget(output_widget)
        splitter.setSizes([150, 180, 220])
        layout.addWidget(splitter, 1)

        manual = QHBoxLayout()
        manual.addWidget(QLabel("手动转换:"))
        manual.addWidget(QLabel("源编码"))
        self.source_combo = QComboBox()
        for label, value in mojibake.ENCODINGS:
            self.source_combo.addItem(label, value)
        manual.addWidget(self.source_combo)
        self.btn_swap = QPushButton("⇄")
        self.btn_swap.setToolTip("交换源编码和目标编码")
        self.btn_swap.clicked.connect(self._swap)
        manual.addWidget(self.btn_swap)
        manual.addWidget(QLabel("目标编码"))
        self.target_combo = QComboBox()
        for label, value in mojibake.ENCODINGS:
            self.target_combo.addItem(label, value)
        self.target_combo.setCurrentIndex(
            self.target_combo.findData("gb18030"))
        manual.addWidget(self.target_combo)
        self.btn_convert = QPushButton("按编码转换")
        self.btn_convert.clicked.connect(self._manual_convert)
        manual.addWidget(self.btn_convert)
        manual.addStretch()
        layout.addLayout(manual)

    def _input_text(self) -> str:
        # QPlainTextEdit.toPlainText() 会把 U+00A0 转成普通空格，而
        # UTF-8 被 Latin-1 解释的乱码经常包含 U+00A0（字节 0xA0）。
        # toRawText() 保留原始字符，否则会永久丢失一个字节，无法修复。
        return self.input_edit.document().toRawText()

    def _auto_analyze(self) -> None:
        text = self._input_text()
        if not text.strip():
            _set_status(self.status, "请先粘贴乱码或 Hex 字节。", "warn")
            return
        mode = self.input_mode.currentData()
        try:
            if mode == "hex":
                raw = mojibake.parse_hex_bytes(text)
                candidates = mojibake.repair_bytes_candidates(raw)
                source_note = f"Hex 字节 {len(raw):,} 字节"
            else:
                candidates = mojibake.repair_candidates(text)
                source_note = f"{len(text):,} 字符"
        except mojibake.MojibakeError as exc:
            self._candidates = []
            self.table.setRowCount(0)
            self.output.clear()
            _set_status(self.status, str(exc), "error")
            return
        self._candidates = candidates
        self.table.setRowCount(len(candidates))
        for row, candidate in enumerate(candidates):
            preview = candidate.text.replace("\n", " ⏎ ").replace("\r", "")
            if len(preview) > 180:
                preview = preview[:180] + "…"
            self.table.setItem(row, 0, QTableWidgetItem(candidate.method))
            self.table.setItem(row, 1, QTableWidgetItem(preview))
            self.table.setItem(row, 2, QTableWidgetItem(f"{candidate.score:.2f}"))
        if not candidates:
            self.output.clear()
            _set_status(
                self.status,
                f"未检测到可修复的明显乱码（{source_note}）。"
                "可以改用手动转换，或确认原文是否已经丢失字节。",
                "warn")
            return
        self.table.selectRow(0)
        self._apply_row(0, 0)
        _set_status(
            self.status,
            f"{source_note}，生成 {len(candidates)} 个候选，已填入最佳结果；"
            "双击其他行切换。",
            "ok")

    def _apply_row(self, row: int, _column: int = 0) -> None:
        if not 0 <= row < len(self._candidates):
            return
        candidate = self._candidates[row]
        self.output.setPlainText(candidate.text)
        _set_status(
            self.status,
            f"已应用：{candidate.method}（评分 {candidate.score:.2f}，"
            f"{mojibake.text_stats(candidate.text)}）",
            "ok")

    def _manual_convert(self) -> None:
        text = self._input_text()
        if not text.strip():
            _set_status(self.status, "请先粘贴要转换的内容。", "warn")
            return
        try:
            result = mojibake.convert_text(
                text,
                self.source_combo.currentData(),
                self.target_combo.currentData(),
                input_is_hex=self.input_mode.currentData() == "hex",
            )
        except mojibake.MojibakeError as exc:
            _set_status(self.status, str(exc), "error")
            return
        self.output.setPlainText(result.text)
        _set_status(
            self.status,
            f"手动转换完成：{result.method}，{mojibake.text_stats(result.text)}",
            "ok")

    def _swap(self) -> None:
        source = self.source_combo.currentIndex()
        target = self.target_combo.currentIndex()
        self.source_combo.setCurrentIndex(target)
        self.target_combo.setCurrentIndex(source)

    def _copy(self) -> None:
        # 同样使用 toRawText()，保留修复结果中的 U+00A0 等不可见字符。
        text = self.output.document().toRawText()
        if not text:
            _set_status(self.status, "当前没有可复制的修复结果。", "warn")
            return
        QGuiApplication.clipboard().setText(text)
        self.btn_copy.setText("已复制 ✓")
        from PySide6.QtCore import QTimer
        QTimer.singleShot(1200, lambda: self.btn_copy.setText("复制结果"))
        _set_status(self.status, f"已复制 {len(text):,} 个字符。", "ok")

    def _clear(self) -> None:
        self._candidates = []
        self.input_edit.clear()
        self.table.setRowCount(0)
        self.output.clear()
        _set_status(self.status, "已清空。", "info")


class DataFileTab(QWidget):
    """Base64/Hex 与图片、ZIP 及其他文件互转。"""

    openFileRequested = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self._decoded: datatools.DecodedPayload | None = None
        self._encoded = ""
        self._source_data = b""
        self._source_path = ""
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_decode_page(), "Base64 / Hex → 文件")
        self.tabs.addTab(self._build_encode_page(), "文件 → Base64 / Hex")
        layout.addWidget(self.tabs)

    # ---------------- 数据 -> 文件 ----------------
    def _build_decode_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        bar = QHBoxLayout()
        bar.addWidget(QLabel("格式:"))
        self.decode_mode = QComboBox()
        self.decode_mode.addItem("自动识别", "auto")
        self.decode_mode.addItem("Base64", "base64")
        self.decode_mode.addItem("Hex", "hex")
        bar.addWidget(self.decode_mode)
        self.btn_decode = QPushButton("解码并预览")
        self.btn_decode.clicked.connect(self._decode)
        bar.addWidget(self.btn_decode)
        self.btn_clear_decode = QPushButton("清空")
        self.btn_clear_decode.clicked.connect(self._clear_decode)
        bar.addWidget(self.btn_clear_decode)
        bar.addStretch()
        self.decode_status = QLabel(
            "支持 data:image/png;base64,...、URL 安全 Base64、0x/空格/逗号分隔的 Hex。")
        self.decode_status.setWordWrap(True)
        bar.addWidget(self.decode_status, 2)
        layout.addLayout(bar)

        self.decode_input = QPlainTextEdit()
        self.decode_input.setPlaceholderText(
            "粘贴 Base64 或 Hex，例如：\n"
            "iVBORw0KGgoAAAANSUhEUg...（Base64 图片）\n"
            "504b0304...（Hex ZIP）")
        self.decode_input.setMaximumHeight(160)
        layout.addWidget(self.decode_input)

        splitter = QSplitter(Qt.Horizontal)
        self.decode_preview = QLabel("图片预览")
        self.decode_preview.setAlignment(Qt.AlignCenter)
        self.decode_preview.setMinimumSize(260, 220)
        self.decode_preview.setStyleSheet("background:#1b1b1b;color:#888;")
        splitter.addWidget(self.decode_preview)

        self.decode_details = QPlainTextEdit()
        self.decode_details.setReadOnly(True)
        self.decode_details.setPlaceholderText(
            "解码后会显示真实文件类型、大小和建议扩展名。\n"
            "图片会直接预览；ZIP/PE 等可保存后打开。")
        splitter.addWidget(self.decode_details)
        splitter.setSizes([350, 650])
        layout.addWidget(splitter, 1)

        actions = QHBoxLayout()
        self.btn_save = QPushButton("保存文件…")
        self.btn_save.clicked.connect(lambda: self._save_decoded(False))
        self.btn_save.setEnabled(False)
        actions.addWidget(self.btn_save)
        self.btn_save_open = QPushButton("保存并分析")
        self.btn_save_open.clicked.connect(lambda: self._save_decoded(True))
        self.btn_save_open.setEnabled(False)
        actions.addWidget(self.btn_save_open)
        self.btn_copy_decoded_hex = QPushButton("复制解码后 Hex")
        self.btn_copy_decoded_hex.clicked.connect(self._copy_decoded_hex)
        self.btn_copy_decoded_hex.setEnabled(False)
        actions.addWidget(self.btn_copy_decoded_hex)
        actions.addStretch()
        layout.addLayout(actions)
        return page

    def _decode(self) -> None:
        text = self.decode_input.toPlainText()
        try:
            payload = datatools.decode_payload(
                text, self.decode_mode.currentData() or "auto")
        except datatools.DataToolError as exc:
            self._decoded = None
            self.decode_preview.setPixmap(QPixmap())
            self.decode_preview.setText("解码失败")
            self.decode_details.clear()
            self.btn_save.setEnabled(False)
            self.btn_save_open.setEnabled(False)
            self.btn_copy_decoded_hex.setEnabled(False)
            _set_status(self.decode_status, str(exc), "error")
            return
        self._decoded = payload
        self._show_decoded(payload)

    def _show_decoded(self, payload: datatools.DecodedPayload) -> None:
        data = payload.data
        lines = [
            f"解码方式 : {payload.method}",
            f"真实类型 : {payload.kind}",
            f"建议扩展 : {payload.extension}",
            f"数据大小 : {datatools.human_size(len(data))}",
            f"默认文件名: {payload.default_name}",
        ]
        if payload.detected.matches:
            lines.append(f"命中签名 : {'、'.join(payload.detected.matches)}")
        if payload.detected.trailing:
            lines.append(
                f"尾随数据 : {payload.detected.trailing.length:,} 字节")
        if payload.warnings:
            lines.append("")
            lines.extend(f"⚠ {warning}" for warning in payload.warnings)
        if payload.is_text:
            lines.append("")
            lines.append("── 文本预览 ──")
            lines.append(data[:8192].decode("utf-8", "replace"))
        self.decode_details.setPlainText("\n".join(lines))

        image = QImage.fromData(data) if payload.is_image else None
        if image is not None and not image.isNull():
            self.decode_preview.setPixmap(_scaled(image, self.decode_preview))
            image_note = f"{image.width()} × {image.height()} 像素"
        elif payload.is_image:
            self.decode_preview.setPixmap(QPixmap())
            self.decode_preview.setText("识别为图片，但本机无法预览")
            image_note = "无法预览"
        else:
            self.decode_preview.setPixmap(QPixmap())
            if payload.is_zip:
                self.decode_preview.setText(
                    "识别为 ZIP\n保存后可在 ZIP 分析页打开")
                image_note = "ZIP 压缩包"
            else:
                self.decode_preview.setText(payload.kind or "二进制数据")
                image_note = payload.kind
        self.btn_save.setEnabled(bool(data))
        self.btn_save_open.setEnabled(bool(data))
        self.btn_copy_decoded_hex.setEnabled(bool(data))
        _set_status(
            self.decode_status,
            f"解码成功：{payload.kind}，{image_note}，"
            f"{datatools.human_size(len(data))}",
            "ok")

    def _save_decoded(self, open_after: bool) -> bool:
        payload = self._decoded
        if payload is None or not payload.data:
            _set_status(self.decode_status, "请先解码出数据。", "warn")
            return False
        ext = payload.extension
        kind = "image" if payload.is_image else (
            "archive" if payload.is_zip else "data")
        saved = save_bytes_dialog(
            self,
            payload.data,
            payload.default_name,
            kind,
            "保存解码后的文件",
            f"{payload.kind} (*{ext});;所有文件 (*.*)",
        )
        if not saved:
            _set_status(
                self.decode_status,
                i18n.tr("保存未完成：已取消，或目标位置不能写入。"
                        "可以换一个位置重试。"),
                "warn")
            return False
        _set_status(
            self.decode_status,
            f"已保存 {len(payload.data):,} 字节到 {saved}",
            "ok")
        if open_after:
            self.openFileRequested.emit(saved)
        return True

    def _copy_decoded_hex(self) -> None:
        if self._decoded is None or not self._decoded.data:
            _set_status(self.decode_status, "当前没有解码数据。", "warn")
            return
        QGuiApplication.clipboard().setText(self._decoded.data.hex())
        _set_status(self.decode_status, "已复制解码后数据的 Hex。", "ok")

    def _clear_decode(self) -> None:
        self._decoded = None
        self.decode_input.clear()
        self.decode_details.clear()
        self.decode_preview.setPixmap(QPixmap())
        self.decode_preview.setText("图片预览")
        self.btn_save.setEnabled(False)
        self.btn_save_open.setEnabled(False)
        self.btn_copy_decoded_hex.setEnabled(False)
        _set_status(self.decode_status, "已清空。", "info")

    # ---------------- 文件 -> 数据 ----------------
    def _build_encode_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        bar = QHBoxLayout()
        self.btn_choose = QPushButton("选择文件…")
        self.btn_choose.clicked.connect(self._choose_file)
        bar.addWidget(self.btn_choose)
        self.encode_file_label = QLabel("未选择文件")
        bar.addWidget(self.encode_file_label, 2)
        bar.addWidget(QLabel("输出:"))
        self.encode_mode = QComboBox()
        self.encode_mode.addItem("Base64", "base64")
        self.encode_mode.addItem("Hex", "hex")
        bar.addWidget(self.encode_mode)
        self.btn_encode = QPushButton("转换")
        self.btn_encode.clicked.connect(self._encode)
        self.btn_encode.setEnabled(False)
        bar.addWidget(self.btn_encode)
        self.btn_copy_encode = QPushButton("复制")
        self.btn_copy_encode.clicked.connect(self._copy_encoded)
        self.btn_copy_encode.setEnabled(False)
        bar.addWidget(self.btn_copy_encode)
        self.btn_save_encode = QPushButton("保存文本…")
        self.btn_save_encode.clicked.connect(self._save_encoded)
        self.btn_save_encode.setEnabled(False)
        bar.addWidget(self.btn_save_encode)
        layout.addLayout(bar)

        self.encode_status = QLabel("选择任意文件，转换成 Base64 或 Hex 文本。")
        self.encode_status.setWordWrap(True)
        layout.addWidget(self.encode_status)
        self.encode_output = QPlainTextEdit()
        self.encode_output.setReadOnly(True)
        self.encode_output.setPlaceholderText("转换结果")
        install_flag_highlighter(self.encode_output)
        layout.addWidget(self.encode_output, 1)
        return page

    def _choose_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "选择要编码的文件")
        if not path:
            return
        try:
            data = datatools.read_file(path)
        except datatools.DataToolError as exc:
            _set_status(self.encode_status, str(exc), "error")
            return
        self._source_path = path
        self._source_data = data
        self.encode_file_label.setText(
            f"{path}  ({datatools.human_size(len(data))})")
        self.btn_encode.setEnabled(True)
        _set_status(self.encode_status, "文件已载入，点击「转换」。", "info")

    def _encode(self) -> None:
        if not self._source_data and not self._source_path:
            _set_status(self.encode_status, "请先选择文件。", "warn")
            return
        try:
            mode = self.encode_mode.currentData() or "base64"
            self._encoded = datatools.encode_data(self._source_data, mode)
        except datatools.DataToolError as exc:
            _set_status(self.encode_status, str(exc), "error")
            return
        self.encode_output.setPlainText(self._encoded)
        self.btn_copy_encode.setEnabled(bool(self._encoded))
        self.btn_save_encode.setEnabled(bool(self._encoded))
        _set_status(
            self.encode_status,
            f"已转换为 {mode.upper()}：{len(self._encoded):,} 字符",
            "ok")

    def _copy_encoded(self) -> None:
        if not self._encoded:
            _set_status(self.encode_status, "当前没有可复制的内容。", "warn")
            return
        QGuiApplication.clipboard().setText(self._encoded)
        _set_status(self.encode_status, "已复制到剪贴板。", "ok")

    def _save_encoded(self) -> None:
        if not self._encoded:
            _set_status(self.encode_status, "当前没有可保存的内容。", "warn")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "保存编码文本", "encoded.txt", "文本 (*.txt);;所有文件 (*.*)")
        if not path:
            return
        if not save_utils.write_bytes(
                self, self._encoded.encode("utf-8"), path, "text"):
            _set_status(self.encode_status, "保存未完成。", "warn")
            return
        _set_status(self.encode_status, f"已保存到 {path}", "ok")


class MiscPanel(QWidget):
    """杂项工具总页签。"""

    openFileRequested = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.tabs = QTabWidget()
        self.qr_tab = QrScanTab()
        self.mojibake_tab = MojibakeTab()
        self.data_tab = DataFileTab()
        self.data_tab.openFileRequested.connect(self.openFileRequested.emit)
        self.tabs.addTab(self.qr_tab, "二维码 / 条码")
        self.tabs.addTab(self.mojibake_tab, "乱码修复")
        self.tabs.addTab(self.data_tab, "Base64 / Hex ↔ 文件")
        layout.addWidget(self.tabs)
