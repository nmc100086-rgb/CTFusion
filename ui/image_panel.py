"""图片隐写页签:预览、基本信息、LSB 位平面/提取、PNG 修复、EXIF、GIF 帧。"""

from __future__ import annotations

import os

from PySide6.QtCore import QBuffer, QIODevice, Qt
from PySide6.QtGui import QImage, QImageReader, QPixmap
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
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import fileparse
from core import imagetools, lsb
from core.filetype import identify
from ui.highlight import install_flag_highlighter, mark_item
from ui.stegsolve_panel import StegSolvePanel

_GIF_MAX_FRAMES = 500


def _fill_table(table: QTableWidget, rows: list[tuple[str, str]]) -> None:
    table.setRowCount(len(rows))
    for row, (key, value) in enumerate(rows):
        table.setItem(row, 0, QTableWidgetItem(key))
        table.setItem(row, 1, QTableWidgetItem(value))


def _scaled_pixmap(image: QImage, label: QLabel) -> QPixmap:
    pixmap = QPixmap.fromImage(image)
    size = label.size()
    if size.width() > 16 and size.height() > 16:
        pixmap = pixmap.scaled(size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
    return pixmap


class ImagePanel(QWidget):
    """图片隐写页签。"""

    def __init__(self) -> None:
        super().__init__()
        self._path = ""
        self._data = b""
        self._payload = b""
        self._prefix = 0
        self._kind = ""
        self._image: QImage | None = None
        self._pixels = b""
        self._channels = 0
        self._channel_names: tuple[str, ...] = ()
        self._width = 0
        self._height = 0
        self._extracted = b""
        self._text_chunks: list[fileparse.PngText] = []
        self._gif_frames: list[QImage] = []
        self._image_buffer: QBuffer | None = None
        self._build_ui()

    # ---------------- UI ----------------
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        bar = QHBoxLayout()
        self.btn_open = QPushButton("打开图片…")
        self.btn_open.clicked.connect(self._choose_file)
        bar.addWidget(self.btn_open)
        self.file_label = QLabel("拖入图片开始分析")
        bar.addWidget(self.file_label, 1)
        layout.addLayout(bar)

        splitter = QSplitter(Qt.Horizontal)
        self.preview = QLabel("图片预览")
        self.preview.setAlignment(Qt.AlignCenter)
        self.preview.setMinimumSize(260, 200)
        self.preview.setStyleSheet("background:#1b1b1b;color:#888;")
        splitter.addWidget(self.preview)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_info(), "基本信息")
        self.tabs.addTab(self._build_lsb(), "LSB 隐写")
        self.tabs.addTab(self._build_row_scan(), "LSB 行信息")
        self.tabs.addTab(self._build_repair(), "图片修复")
        self.tabs.addTab(self._build_chunks(), "PNG Chunk")
        self.tabs.addTab(self._build_tools(), "图像工具")
        self.stegsolve = StegSolvePanel()
        self.tabs.addTab(self.stegsolve, "StegSolve")
        self.tabs.addTab(self._build_exif(), "EXIF")
        self.tabs.addTab(self._build_frames(), "GIF 帧")
        splitter.addWidget(self.tabs)
        splitter.setSizes([360, 740])
        layout.addWidget(splitter, 1)

    def _build_info(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.info_table = QTableWidget(0, 2)
        self.info_table.setHorizontalHeaderLabels(["项目", "值"])
        self.info_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.info_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.info_table.verticalHeader().setVisible(False)
        self.info_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.info_table)
        return page

    def _build_lsb(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        bar = QHBoxLayout()
        bar.addWidget(QLabel("通道:"))
        self.lsb_channel = QComboBox()
        self.lsb_channel.setMinimumWidth(80)
        self.lsb_channel.currentIndexChanged.connect(self._update_capacity)
        bar.addWidget(self.lsb_channel)
        bar.addWidget(QLabel("位:"))
        self.lsb_bit = QComboBox()
        self.lsb_bit.addItems([str(i) for i in range(8)])
        bar.addWidget(self.lsb_bit)
        bar.addWidget(QLabel("位序:"))
        self.lsb_order = QComboBox()
        self.lsb_order.addItem("MSB-first", "msb")
        self.lsb_order.addItem("LSB-first", "lsb")
        bar.addWidget(self.lsb_order)
        self.btn_bitplane = QPushButton("显示位平面")
        self.btn_bitplane.clicked.connect(self._on_bitplane)
        bar.addWidget(self.btn_bitplane)
        self.btn_extract = QPushButton("提取 LSB 数据")
        self.btn_extract.clicked.connect(self._on_extract)
        bar.addWidget(self.btn_extract)
        bar.addStretch()
        layout.addLayout(bar)

        options = QHBoxLayout()
        options.addWidget(QLabel("起始像素:"))
        self.lsb_start = QSpinBox()
        self.lsb_start.setRange(0, 2 ** 31 - 1)
        self.lsb_start.setToolTip("从第几个像素开始提取")
        self.lsb_start.valueChanged.connect(self._update_capacity)
        options.addWidget(self.lsb_start)
        options.addWidget(QLabel("步长:"))
        self.lsb_step = QSpinBox()
        self.lsb_step.setRange(1, 10000)
        self.lsb_step.setValue(1)
        self.lsb_step.setToolTip("每隔多少个像素取一个")
        self.lsb_step.valueChanged.connect(self._update_capacity)
        options.addWidget(self.lsb_step)
        options.addWidget(QLabel("最多字节:"))
        self.lsb_max = QSpinBox()
        self.lsb_max.setRange(0, 2 ** 31 - 1)
        self.lsb_max.setSpecialValueText("全部")
        self.lsb_max.setValue(0)
        options.addWidget(self.lsb_max)
        options.addWidget(QLabel("文本编码:"))
        self.lsb_encoding = QComboBox()
        for label, value in (
            ("自动", "auto"), ("UTF-8", "utf-8"),
            ("UTF-16 LE", "utf-16-le"), ("UTF-16 BE", "utf-16-be"),
            ("GB18030", "gb18030"), ("Latin-1", "latin-1"),
        ):
            self.lsb_encoding.addItem(label, value)
        options.addWidget(self.lsb_encoding)
        options.addWidget(QLabel("帧:"))
        self.lsb_frame = QComboBox()
        self.lsb_frame.setEnabled(False)
        self.lsb_frame.currentIndexChanged.connect(self._on_lsb_frame)
        options.addWidget(self.lsb_frame)
        options.addStretch()
        layout.addLayout(options)

        self.lsb_capacity = QLabel("单通道最低位容量:—")
        layout.addWidget(self.lsb_capacity)

        self.lsb_preview = QLabel("位平面预览")
        self.lsb_preview.setAlignment(Qt.AlignCenter)
        self.lsb_preview.setMinimumHeight(150)
        self.lsb_preview.setStyleSheet("background:#1b1b1b;color:#888;")
        layout.addWidget(self.lsb_preview, 1)

        out_bar = QHBoxLayout()
        out_bar.addWidget(QLabel("提取结果:"))
        out_bar.addStretch()
        self.btn_save_lsb = QPushButton("保存提取数据…")
        self.btn_save_lsb.clicked.connect(self._on_save_lsb)
        out_bar.addWidget(self.btn_save_lsb)
        layout.addLayout(out_bar)

        self.lsb_output = QPlainTextEdit()
        self.lsb_output.setReadOnly(True)
        self.lsb_output.setPlaceholderText("点击「提取 LSB 数据」后显示文本或 Hex 预览")
        install_flag_highlighter(self.lsb_output)
        layout.addWidget(self.lsb_output, 1)
        return page

    def _build_row_scan(self) -> QWidget:
        """随波逐流式“图片 LSB row 信息”:遍历通道顺序并显示文本行。"""
        page = QWidget()
        layout = QVBoxLayout(page)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("位:"))
        self.row_bit = QComboBox()
        self.row_bit.addItems([str(i) for i in range(8)])
        bar.addWidget(self.row_bit)
        bar.addWidget(QLabel("位序:"))
        self.row_order = QComboBox()
        self.row_order.addItem("MSB-first", "msb")
        self.row_order.addItem("LSB-first", "lsb")
        bar.addWidget(self.row_order)
        bar.addWidget(QLabel("模式:"))
        self.row_mode = QComboBox()
        self.row_mode.addItem("整图通道顺序", "whole")
        self.row_mode.addItem("逐行扫描", "rows")
        bar.addWidget(self.row_mode)
        bar.addWidget(QLabel("每行最多字节:"))
        self.row_max = QSpinBox()
        self.row_max.setRange(32, 4096)
        self.row_max.setValue(256)
        bar.addWidget(self.row_max)
        self.btn_row_scan = QPushButton("扫描 LSB 行信息")
        self.btn_row_scan.clicked.connect(self._on_row_scan)
        bar.addWidget(self.btn_row_scan)
        bar.addStretch()
        layout.addLayout(bar)

        self.row_scan_status = QLabel(
            "遍历 R/G/B/A 通道顺序,提取 LSB 文本;flag 行会排在最前并高亮。")
        layout.addWidget(self.row_scan_status)
        self.row_scan_output = QPlainTextEdit()
        self.row_scan_output.setReadOnly(True)
        self.row_scan_output.setPlaceholderText("点击「扫描 LSB 行信息」")
        install_flag_highlighter(self.row_scan_output)
        layout.addWidget(self.row_scan_output, 1)
        return page

    def _on_row_scan(self) -> None:
        if not self._pixels:
            self.row_scan_status.setText("请先载入图片")
            return
        results = lsb.scan_orders(
            self._pixels, self._channels, self._channel_names,
            bit=self.row_bit.currentIndex(),
            bit_order=self.row_order.currentData() or "msb",
            max_bytes=self.row_max.value(),
            rows=self.row_mode.currentData() == "rows",
            width=self._width,
        )
        if not results:
            self.row_scan_output.setPlainText("(没有可显示的结果)")
            self.row_scan_status.setText("没有可显示的结果")
            return
        lines = [f"{item.label}: {item.text}" for item in results]
        self.row_scan_output.setPlainText("\n".join(lines))
        flag_lines = sum(1 for item in results if item.has_flag)
        self.row_scan_status.setText(
            f"共 {len(results)} 行;其中 {flag_lines} 行命中 flag/ctf。"
            " 通道顺序按 R/G/B/A 排列,逐行模式只显示高可打印或命中 flag 的行。")

    def _build_repair(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        self.repair_hint = QLabel("仅 PNG 支持 CRC 与宽高校验/修复")
        layout.addWidget(self.repair_hint)

        self.crc_table = QTableWidget(0, 4)
        self.crc_table.setHorizontalHeaderLabels(["Chunk", "偏移", "存储 CRC", "实际 CRC"])
        self.crc_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.crc_table.verticalHeader().setVisible(False)
        self.crc_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.crc_table.setMaximumHeight(160)
        layout.addWidget(self.crc_table)

        size_bar = QHBoxLayout()
        size_bar.addWidget(QLabel("宽:"))
        self.spin_width = QSpinBox()
        self.spin_width.setRange(1, 2 ** 31 - 1)
        size_bar.addWidget(self.spin_width)
        size_bar.addWidget(QLabel("高:"))
        self.spin_height = QSpinBox()
        self.spin_height.setRange(1, 2 ** 31 - 1)
        size_bar.addWidget(self.spin_height)
        size_bar.addStretch()
        layout.addLayout(size_bar)

        btn_bar = QHBoxLayout()
        self.btn_fix_crc = QPushButton("修复全部 CRC 并另存…")
        self.btn_fix_crc.clicked.connect(self._on_fix_crc)
        btn_bar.addWidget(self.btn_fix_crc)
        self.btn_fix_size = QPushButton("按上述宽高修复并另存…")
        self.btn_fix_size.clicked.connect(self._on_fix_size)
        btn_bar.addWidget(self.btn_fix_size)
        self.btn_auto_size = QPushButton("按 IDAT 自动推算宽高…")
        self.btn_auto_size.clicked.connect(self._on_auto_size)
        btn_bar.addWidget(self.btn_auto_size)
        btn_bar.addStretch()
        layout.addLayout(btn_bar)

        self.repair_log = QPlainTextEdit()
        self.repair_log.setReadOnly(True)
        self.repair_log.setPlaceholderText("修复操作记录")
        install_flag_highlighter(self.repair_log)
        layout.addWidget(self.repair_log, 1)
        return page

    def _build_chunks(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        bar = QHBoxLayout()
        self.chunk_hint = QLabel("仅 PNG 支持 Chunk 列表与文本块提取")
        bar.addWidget(self.chunk_hint, 1)
        self.btn_export_chunks = QPushButton("导出文本 Chunk…")
        self.btn_export_chunks.clicked.connect(self._on_export_chunks)
        self.btn_export_chunks.setEnabled(False)
        bar.addWidget(self.btn_export_chunks)
        layout.addLayout(bar)

        self.chunk_table = QTableWidget(0, 5)
        self.chunk_table.setHorizontalHeaderLabels(
            ["Chunk", "偏移", "大小", "CRC", "内容"])
        self.chunk_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.chunk_table.verticalHeader().setVisible(False)
        self.chunk_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.chunk_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        layout.addWidget(self.chunk_table)
        return page

    def _refresh_chunks(self) -> None:
        self.chunk_table.setRowCount(0)
        self._text_chunks: list[fileparse.PngText] = []
        if self._kind != "PNG":
            self.chunk_hint.setText("仅 PNG 支持 Chunk 列表与文本块提取")
            self.btn_export_chunks.setEnabled(False)
            return
        chunks = fileparse.png_chunks(self._payload)
        texts = {item.offset: item for item in fileparse.png_text_chunks(self._payload)}
        self._text_chunks = list(texts.values())
        self.chunk_hint.setText(f"共 {len(chunks)} 个 chunk,其中 {len(texts)} 个文本/EXIF 块")
        self.chunk_table.setRowCount(len(chunks))
        for row, chunk in enumerate(chunks):
            text = texts.get(chunk.offset)
            if text:
                content = text.text[:300]
            elif chunk.name == "acTL":
                content = "APNG 动画控制块"
            elif chunk.name == "fcTL":
                content = "APNG 帧控制块"
            elif chunk.name == "fdAT":
                content = "APNG 帧数据块"
            else:
                content = ""
            crc = (f"{chunk.stored_crc:08X}" if chunk.stored_crc is not None else "—")
            values = [chunk.name, f"0x{self._prefix + chunk.offset:X}",
                      f"{chunk.length:,}", crc, content]
            for col, value in enumerate(values):
                cell = QTableWidgetItem(value)
                if col == 4:
                    mark_item(cell)
                self.chunk_table.setItem(row, col, cell)
        self.btn_export_chunks.setEnabled(bool(texts))

    def _on_export_chunks(self) -> None:
        if not self._text_chunks:
            return
        base, _ = os.path.splitext(self._path)
        path, _ = QFileDialog.getSaveFileName(
            self, "导出文本 Chunk", (base or "png") + "_chunks.txt",
            "文本 (*.txt)")
        if not path:
            return
        lines = []
        for item in self._text_chunks:
            lines.append(f"[{item.chunk}] {item.keyword}\n{item.text}\n")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
        except OSError as e:
            QMessageBox.warning(self, "CTFusion", f"导出失败:{e}")
            return
        QMessageBox.information(self, "CTFusion", f"已导出:\n{path}")

    def _build_tools(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("通道:"))
        self.tool_channel = QComboBox()
        for name, index in (("R", 0), ("G", 1), ("B", 2), ("A", 3)):
            self.tool_channel.addItem(name, index)
        bar.addWidget(self.tool_channel)
        self.btn_channel = QPushButton("预览通道")
        self.btn_channel.clicked.connect(self._on_channel_image)
        bar.addWidget(self.btn_channel)
        self.btn_invert = QPushButton("反色")
        self.btn_invert.clicked.connect(self._on_invert)
        bar.addWidget(self.btn_invert)
        self.btn_xor = QPushButton("与另一张图 XOR…")
        self.btn_xor.clicked.connect(self._on_xor)
        bar.addWidget(self.btn_xor)
        self.btn_diff = QPushButton("差分…")
        self.btn_diff.clicked.connect(self._on_difference)
        bar.addWidget(self.btn_diff)
        self.btn_hist = QPushButton("直方图")
        self.btn_hist.clicked.connect(self._on_histogram)
        bar.addWidget(self.btn_hist)
        self.btn_save_tool = QPushButton("保存结果…")
        self.btn_save_tool.clicked.connect(self._on_save_tool)
        self.btn_save_tool.setEnabled(False)
        bar.addWidget(self.btn_save_tool)
        bar.addStretch()
        layout.addLayout(bar)

        self.tool_preview = QLabel("通道 / XOR / 差分结果预览")
        self.tool_preview.setAlignment(Qt.AlignCenter)
        self.tool_preview.setStyleSheet("background:#1b1b1b;color:#888;")
        layout.addWidget(self.tool_preview, 1)
        self.tool_log = QPlainTextEdit()
        self.tool_log.setReadOnly(True)
        self.tool_log.setMaximumHeight(120)
        install_flag_highlighter(self.tool_log)
        layout.addWidget(self.tool_log)
        self._tool_image: QImage | None = None
        return page

    def _refresh_tools(self) -> None:
        enabled = self._image is not None
        for button in (self.btn_channel, self.btn_invert, self.btn_xor,
                       self.btn_diff, self.btn_hist):
            button.setEnabled(enabled)
        self._tool_image = None
        self.btn_save_tool.setEnabled(False)
        self.tool_preview.setPixmap(QPixmap())
        self.tool_preview.setText("通道 / XOR / 差分结果预览")
        self.tool_log.clear()

    def _show_tool_image(self, image: QImage, note: str) -> None:
        self._tool_image = image
        self.tool_preview.setPixmap(_scaled_pixmap(image, self.tool_preview))
        self.btn_save_tool.setEnabled(True)
        self.tool_log.appendPlainText(note)

    def _on_channel_image(self) -> None:
        if self._image is None:
            return
        channel = self.tool_channel.currentData() or 0
        image = imagetools.channel_image(self._image, channel)
        self._show_tool_image(image, f"通道 {self.tool_channel.currentText()} 灰度图")

    def _on_invert(self) -> None:
        if self._image is None:
            return
        self._show_tool_image(imagetools.invert(self._image), "RGB 反色")

    def _other_image(self) -> QImage | None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择另一张图", "",
            "图片 (*.png *.jpg *.jpeg *.bmp *.gif *.webp *.tif *.tiff)")
        if not path:
            return None
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            QMessageBox.warning(self, "CTFusion", f"读取失败:{e}")
            return None
        image = QImage.fromData(data)
        if image.isNull():
            QMessageBox.warning(self, "CTFusion", "无法解码该图片")
            return None
        return image

    def _on_xor(self) -> None:
        if self._image is None:
            return
        other = self._other_image()
        if other is None:
            return
        result = imagetools.xor_images(self._image, other)
        if result is None:
            QMessageBox.warning(self, "CTFusion", "两张图片尺寸必须相同")
            return
        self._show_tool_image(result, "XOR 结果(相同像素为黑)")

    def _on_difference(self) -> None:
        if self._image is None:
            return
        other = self._other_image()
        if other is None:
            return
        result = imagetools.difference(self._image, other)
        if result is None:
            QMessageBox.warning(self, "CTFusion", "两张图片尺寸必须相同")
            return
        self._show_tool_image(result, "差分结果(|A-B|)")

    def _on_histogram(self) -> None:
        if self._image is None:
            return
        counts = imagetools.histogram(self._image)
        lines = [f"{i * 16:3d}-{i * 16 + 15:3d}: {sum(counts[i * 16:i * 16 + 16]):,}"
                 for i in range(16)]
        self.tool_log.setPlainText("RGB 直方图(16 区间):\n" + "\n".join(lines))

    def _on_save_tool(self) -> None:
        if self._tool_image is None:
            return
        base, _ = os.path.splitext(self._path)
        path, _ = QFileDialog.getSaveFileName(
            self, "保存图像结果", (base or "image") + "_tool.png", "PNG (*.png)")
        if not path:
            return
        if not self._tool_image.save(path, "PNG"):
            QMessageBox.warning(self, "CTFusion", "保存失败")
            return
        self.tool_log.appendPlainText(f"已保存:{path}")

    def _build_exif(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.exif_table = QTableWidget(0, 2)
        self.exif_table.setHorizontalHeaderLabels(["字段", "值"])
        self.exif_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.exif_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.exif_table.verticalHeader().setVisible(False)
        self.exif_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.exif_table)
        return page

    def _build_frames(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("帧:"))
        self.frame_combo = QComboBox()
        self.frame_combo.currentIndexChanged.connect(self._on_frame_changed)
        bar.addWidget(self.frame_combo, 1)
        layout.addLayout(bar)
        self.frame_preview = QLabel("载入 GIF 后可逐帧查看")
        self.frame_preview.setAlignment(Qt.AlignCenter)
        self.frame_preview.setStyleSheet("background:#1b1b1b;color:#888;")
        layout.addWidget(self.frame_preview, 1)
        return page

    # ---------------- 载入 ----------------
    def _choose_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择图片",
            "", "图片 (*.png *.jpg *.jpeg *.gif *.bmp *.webp *.tif *.tiff)")
        if path:
            self.load_file(path)

    def load_file(self, path: str) -> None:
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            QMessageBox.warning(self, "CTFusion", f"读取文件失败:{e}")
            return
        result = identify(data, os.path.basename(path))
        self._path = path
        self._data = data
        self._prefix = result.prefix
        self._payload = data[result.prefix:]
        self._kind = result.real_name
        label = f"{self._path}  ({len(data):,} 字节)  |  {self._kind}"
        if self._prefix:
            label += f"  [前置数据 {self._prefix} 字节]"
        self.file_label.setText(label)
        self._load_image()
        self.stegsolve.set_image(self._image)
        self._refresh_info()
        self._refresh_repair()
        self._refresh_chunks()
        self._refresh_tools()
        self._refresh_exif()
        self._refresh_frames()
        self.btn_bitplane.setEnabled(bool(self._pixels))
        self.btn_extract.setEnabled(bool(self._pixels))
        self.lsb_preview.setText("位平面预览")
        self.lsb_preview.setPixmap(QPixmap())
        self.lsb_output.setPlainText("")
        if self._kind == "JPEG":
            self.lsb_output.setPlainText(
                "提示:JPEG 是有损压缩,解码后的像素 LSB 不能可靠保留隐藏数据;\n"
                "以下提取结果仅供排查,建议优先使用 PNG/BMP 原图。")
        self._extracted = b""

    def _load_image(self) -> None:
        # 先用 QImageReader 检查尺寸,避免解码超大像素图时直接耗尽内存。
        self._image = None
        if self._payload:
            buffer = QBuffer()
            buffer.setData(self._payload)
            buffer.open(QIODevice.ReadOnly)
            reader = QImageReader(buffer)
            size = reader.size()
            if size.isValid() and size.width() * size.height() > 120_000_000:
                self._pixels = b""
                self._channels = 0
                self._width = self._height = 0
                self.preview.setPixmap(QPixmap())
                self.preview.setText("图片像素数超过 1.2 亿,已停止预览")
                return
            image = reader.read()
            if image is not None and not image.isNull():
                self._image = image
                self._image_buffer = buffer
        if self._image is None or self._image.isNull():
            self._image = None
            self._pixels = b""
            self._channels = 0
            self._width = self._height = 0
            self.preview.setPixmap(QPixmap())
            self.preview.setText("无法预览该图片")
            return
        self._width = self._image.width()
        self._height = self._image.height()
        self._set_pixels(self._image)
        self._update_preview()

    def _packed_bytes(self, image: QImage, channels: int) -> bytes:
        raw = bytes(image.constBits())
        stride = image.bytesPerLine()
        row_bytes = image.width() * channels
        if stride == row_bytes:
            return raw[:row_bytes * image.height()]
        return b"".join(
            raw[y * stride:y * stride + row_bytes]
            for y in range(image.height())
        )

    def _set_pixels(self, image: QImage) -> None:
        """保存当前帧的原始像素字节。

        不再一律转 RGBA8888:索引色保留索引字节,16-bit 保留原始低/高字节,
        这样 LSB 提取不会在转换阶段丢掉隐藏数据。
        """
        self._width = image.width()
        self._height = image.height()
        fmt = image.format()
        if fmt == QImage.Format_Indexed8:
            data = bytes(
                image.pixelIndex(x, y)
                for y in range(image.height())
                for x in range(image.width())
            )
            channels = 1
            names = ("索引",)
        elif fmt == QImage.Format_Grayscale8:
            data = self._packed_bytes(image, 1)
            channels = 1
            names = ("灰度",)
        elif fmt == QImage.Format_Grayscale16:
            data = self._packed_bytes(image, 2)
            channels = 2
            names = ("灰度低", "灰度高")
        elif image.depth() > 32:
            rgba = image.convertToFormat(QImage.Format_RGBA64)
            data = self._packed_bytes(rgba, 8)
            channels = 8
            names = ("R低", "R高", "G低", "G高",
                     "B低", "B高", "A低", "A高")
        else:
            rgba = image.convertToFormat(QImage.Format_RGBA8888)
            data = self._packed_bytes(rgba, 4)
            channels = 4
            names = ("R", "G", "B", "A")
        self._pixels = data
        self._channels = channels
        self._channel_names = names
        total_pixels = self._width * self._height
        self.lsb_start.setMaximum(max(0, total_pixels - 1))
        if self.lsb_start.value() >= total_pixels:
            self.lsb_start.setValue(0)
        self._populate_channels()

    def _populate_channels(self) -> None:
        old = self.lsb_channel.currentIndex()
        self.lsb_channel.blockSignals(True)
        self.lsb_channel.clear()
        for index, name in enumerate(self._channel_names):
            self.lsb_channel.addItem(name, index)
        if self._channels == 4:
            self.lsb_channel.addItem("RGB", (0, 1, 2))
            self.lsb_channel.addItem("RGBA", (0, 1, 2, 3))
        elif self._channels > 1:
            self.lsb_channel.addItem("全部通道", tuple(range(self._channels)))
        if 0 <= old < self.lsb_channel.count():
            self.lsb_channel.setCurrentIndex(old)
        self.lsb_channel.blockSignals(False)
        self._update_capacity()

    def _selected_channels(self) -> list[int]:
        data = self.lsb_channel.currentData()
        if isinstance(data, tuple):
            return [int(item) for item in data]
        if isinstance(data, int):
            return [data]
        return [0]

    def _update_capacity(self) -> None:
        if not hasattr(self, "lsb_capacity"):
            return
        if not self._pixels or not self._width or not self._height:
            self.lsb_capacity.setText("单通道最低位容量:—")
            return
        channels = max(1, len(self._selected_channels()))
        start = self.lsb_start.value() if hasattr(self, "lsb_start") else 0
        step = self.lsb_step.value() if hasattr(self, "lsb_step") else 1
        total_pixels = self._width * self._height
        usable = max(0, (total_pixels - min(start, total_pixels) + step - 1) // step)
        capacity = usable * channels // 8
        prefix = "所选通道" if channels > 1 else "单通道"
        self.lsb_capacity.setText(f"{prefix}最低位容量:{capacity:,} 字节")

    def _on_lsb_frame(self, index: int) -> None:
        if not self._gif_frames or index < 0 or index >= len(self._gif_frames):
            return
        self._set_pixels(self._gif_frames[index])
        self._show_frame(index)

    def _update_preview(self) -> None:
        if self._image is None:
            return
        self.preview.setPixmap(_scaled_pixmap(self._image, self.preview))

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._update_preview()

    # ---------------- 基本信息 ----------------
    def _refresh_info(self) -> None:
        rows = fileparse.image_info(self._kind, self._payload)
        if self._width:
            rows.append(("像素总数", f"{self._width * self._height:,}"))
        if not rows:
            rows = [("提示", "该格式暂不支持基本信息解析")]
        _fill_table(self.info_table, rows)
        self._update_capacity()

    # ---------------- LSB ----------------
    def _on_bitplane(self) -> None:
        if not self._pixels:
            return
        channels = self._selected_channels()
        channel = channels[0]
        bit = self.lsb_bit.currentIndex()
        plane = lsb.bit_plane(self._pixels, self._channels, channel, bit)
        image = QImage(plane, self._width, self._height,
                       self._width, QImage.Format_Grayscale8).copy()
        self.lsb_preview.setPixmap(_scaled_pixmap(image, self.lsb_preview))

    def _on_extract(self) -> None:
        if not self._pixels:
            return
        channels = self._selected_channels()
        bit = self.lsb_bit.currentIndex()
        self._extracted = lsb.extract_bytes(
            self._pixels, self._channels, channels[0], bit,
            max_bytes=self.lsb_max.value(),
            bit_order=self.lsb_order.currentData() or "msb",
            start_pixel=self.lsb_start.value(),
            pixel_step=self.lsb_step.value(),
            channels_sel=channels,
        )
        text = lsb.preview(
            self._extracted,
            encoding=self.lsb_encoding.currentData() or "auto",
        )
        self.lsb_output.setPlainText(
            f"通道 {self.lsb_channel.currentText()} / 第 {bit} 位 / "
            f"{self.lsb_order.currentText()}\n\n{text}")

    def _on_save_lsb(self) -> None:
        if not self._extracted:
            QMessageBox.information(self, "CTFusion", "请先提取 LSB 数据")
            return
        base = os.path.splitext(self._path)[0] or "lsb"
        path, _ = QFileDialog.getSaveFileName(self, "保存提取数据", base + "_lsb.bin")
        if not path:
            return
        try:
            with open(path, "wb") as f:
                f.write(self._extracted)
        except OSError as e:
            QMessageBox.warning(self, "CTFusion", f"保存失败:{e}")
            return
        QMessageBox.information(self, "CTFusion", f"已保存 {len(self._extracted):,} 字节:\n{path}")

    # ---------------- PNG 修复 ----------------
    def _refresh_repair(self) -> None:
        self.crc_table.setRowCount(0)
        self.repair_log.setPlainText("")
        info = fileparse.png_info(self._payload) if self._kind == "PNG" else None
        is_png = info is not None
        for button in (self.btn_fix_crc, self.btn_fix_size, self.btn_auto_size):
            button.setEnabled(is_png)
        self.spin_width.setEnabled(is_png)
        self.spin_height.setEnabled(is_png)
        if not is_png:
            self.repair_hint.setText("仅 PNG 支持 CRC 与宽高校验/修复")
            return
        self.repair_hint.setText(
            f"IHDR:{info.width} x {info.height} | 位深 {info.bit_depth} | "
            f"{info.color_name} | chunk {info.chunk_count} 个")
        self.spin_width.setValue(max(1, info.width))
        self.spin_height.setValue(max(1, info.height))
        rows = [(c.name, f"0x{self._prefix + c.offset:X}",
                 f"{c.stored_crc:08X}", f"{c.calc_crc:08X}")
                for c in info.crc_errors if c.stored_crc is not None]
        self.crc_table.setRowCount(len(rows))
        for row, values in enumerate(rows):
            for col, value in enumerate(values):
                self.crc_table.setItem(row, col, QTableWidgetItem(value))
        if info.crc_errors:
            self._log(f"⚠ 发现 {len(info.crc_errors)} 个 chunk CRC 错误")
        else:
            self._log("✓ 所有 chunk 的 CRC 校验通过")
        if info.truncated:
            self._log("⚠ 文件存在截断的 chunk,部分修复可能失败")
        candidates = fileparse.png_size_candidates(self._payload) if is_png else []
        actual = candidates[0] if candidates else None
        if actual:
            if actual != (info.width, info.height):
                self._log(f"⚠ IDAT 推算出的实际像素尺寸为 {actual[0]} x {actual[1]},"
                          f"与 IHDR 不符(常见于宽高被篡改)")
            else:
                self._log(f"IDAT 推算尺寸 {actual[0]} x {actual[1]},与 IHDR 一致")
            if len(candidates) > 1:
                preview = "、".join(f"{w}x{h}" for w, h in candidates[:8])
                self._log(f"  其他候选:{preview}"
                          + ("…" if len(candidates) > 8 else ""))

    def _log(self, text: str) -> None:
        self.repair_log.appendPlainText(text)

    def _save_bytes(self, data: bytes, suffix: str) -> str | None:
        base, ext = os.path.splitext(self._path)
        default = f"{base}_{suffix}{ext or '.png'}"
        path, _ = QFileDialog.getSaveFileName(self, "保存修复后的文件", default)
        if not path:
            return None
        try:
            with open(path, "wb") as f:
                if self._prefix:
                    f.write(self._data[:self._prefix])
                f.write(data)
        except OSError as e:
            QMessageBox.warning(self, "CTFusion", f"保存失败:{e}")
            return None
        return path

    def _on_fix_crc(self) -> None:
        info = fileparse.png_info(self._payload)
        if info is None:
            return
        if not info.crc_errors:
            QMessageBox.information(self, "CTFusion", "所有 chunk 的 CRC 均正确,无需修复")
            return
        fixed = fileparse.repair_png_crc(self._payload)
        path = self._save_bytes(fixed, "crcfix")
        if not path:
            return
        self._log(f"✓ 已修复 {len(info.crc_errors)} 个 CRC 并保存:{path}")
        QMessageBox.information(self, "CTFusion", f"CRC 修复完成:\n{path}")

    def _on_fix_size(self) -> None:
        if self._kind != "PNG":
            return
        width, height = self.spin_width.value(), self.spin_height.value()
        fixed = fileparse.repair_png_dimensions(self._payload, width, height)
        path = self._save_bytes(fixed, f"{width}x{height}")
        if not path:
            return
        self._log(f"✓ 已将 IHDR 改为 {width} x {height} 并重算 CRC:{path}")
        QMessageBox.information(self, "CTFusion", f"宽高修复完成:\n{path}")

    def _on_auto_size(self) -> None:
        info = fileparse.png_info(self._payload)
        candidates = fileparse.png_size_candidates(self._payload)
        if info is None or not candidates:
            QMessageBox.warning(self, "CTFusion", "无法从 IDAT 推算尺寸(可能已截断或为隔行 PNG)")
            return
        actual = candidates[0]
        if actual == (info.width, info.height):
            QMessageBox.information(
                self, "CTFusion",
                f"IHDR 与 IDAT 推算一致({actual[0]} x {actual[1]}),无需修复")
            return
        if len(candidates) > 1:
            preview = "\n".join(f"  {w} x {h}" for w, h in candidates[:8])
            choice = QMessageBox.question(
                self, "CTFusion",
                f"检测到 {len(candidates)} 个可能的尺寸,优先候选为 "
                f"{actual[0]} x {actual[1]}:\n{preview}\n\n"
                "是否使用该候选修复?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes,
            )
            if choice != QMessageBox.Yes:
                return
        self.spin_width.setValue(actual[0])
        self.spin_height.setValue(actual[1])
        fixed = fileparse.repair_png_dimensions(self._payload, actual[0], actual[1])
        path = self._save_bytes(fixed, f"{actual[0]}x{actual[1]}")
        if not path:
            return
        self._log(f"✓ 已按 IDAT 推算尺寸 {actual[0]} x {actual[1]} 修复:{path}")
        QMessageBox.information(self, "CTFusion", f"宽高自动修复完成:\n{path}")

    # ---------------- EXIF ----------------
    def _refresh_exif(self) -> None:
        rows = (fileparse.parse_exif(self._payload)
                if self._kind in ("JPEG", "PNG", "TIFF") else [])
        if not rows:
            rows = [("提示", "未发现 EXIF 数据(支持 JPEG APP1 / PNG eXIf / TIFF)")]
        _fill_table(self.exif_table, rows)

    # ---------------- GIF 帧 ----------------
    def _refresh_frames(self) -> None:
        self.frame_combo.blockSignals(True)
        self.frame_combo.clear()
        self.lsb_frame.blockSignals(True)
        self.lsb_frame.clear()
        self._gif_frames = []
        if self._kind != "GIF":
            self.frame_combo.addItem("仅 GIF 支持逐帧查看")
            self.frame_combo.setEnabled(False)
            self.lsb_frame.addItem("仅 GIF")
            self.lsb_frame.setEnabled(False)
            self.frame_preview.setPixmap(QPixmap())
            self.frame_preview.setText("仅 GIF 支持逐帧查看")
            self.frame_combo.blockSignals(False)
            self.lsb_frame.blockSignals(False)
            return
        buffer = QBuffer()
        buffer.setData(self._payload)
        buffer.open(QIODevice.ReadOnly)
        reader = QImageReader(buffer)
        count = reader.imageCount()
        # Qt 的 GIF 插件不支持随机 jumpToImage,但可以顺序 read。
        # 一次性读入帧缓存,避免切回第 1 帧时读到下一帧。
        limit = min(count if count > 0 else _GIF_MAX_FRAMES, _GIF_MAX_FRAMES)
        for _ in range(limit):
            image = reader.read()
            if image.isNull():
                break
            self._gif_frames.append(image)
        if not self._gif_frames:
            self.frame_combo.addItem("无法读取帧")
            self.frame_combo.setEnabled(False)
            self.lsb_frame.addItem("无法读取帧")
            self.lsb_frame.setEnabled(False)
            self.frame_combo.blockSignals(False)
            self.lsb_frame.blockSignals(False)
            return
        for i in range(len(self._gif_frames)):
            self.frame_combo.addItem(f"第 {i + 1} 帧")
            self.lsb_frame.addItem(f"第 {i + 1} 帧", i)
        self.frame_combo.setEnabled(True)
        self.lsb_frame.setEnabled(True)
        self.frame_combo.setCurrentIndex(0)
        self.lsb_frame.setCurrentIndex(0)
        self.frame_combo.blockSignals(False)
        self.lsb_frame.blockSignals(False)
        self._show_frame(0)

    def _show_frame(self, index: int) -> None:
        if index < 0 or index >= len(self._gif_frames):
            return
        image = self._gif_frames[index]
        if image.isNull():
            self.frame_preview.setPixmap(QPixmap())
            self.frame_preview.setText("无法读取该帧")
            return
        self.frame_preview.setPixmap(_scaled_pixmap(image, self.frame_preview))

    def _sync_frame_combos(self, index: int, source: QComboBox) -> None:
        other = self.lsb_frame if source is self.frame_combo else self.frame_combo
        other.blockSignals(True)
        other.setCurrentIndex(index)
        other.blockSignals(False)

    def _on_frame_changed(self, index: int) -> None:
        if index < 0 or index >= len(self._gif_frames):
            return
        self._show_frame(index)
        self._set_pixels(self._gif_frames[index])
        self.stegsolve.set_image(self._gif_frames[index])
        self._sync_frame_combos(index, self.frame_combo)

    def _on_lsb_frame(self, index: int) -> None:
        if index < 0 or index >= len(self._gif_frames):
            return
        self._set_pixels(self._gif_frames[index])
        self._show_frame(index)
        self.stegsolve.set_image(self._gif_frames[index])
        self._sync_frame_combos(index, self.lsb_frame)
