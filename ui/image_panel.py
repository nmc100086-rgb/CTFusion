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
from core import lsb
from core.filetype import identify

_IMAGE_KINDS = ("PNG", "JPEG", "GIF", "BMP", "WEBP", "TIFF")


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
        self._kind = ""
        self._image: QImage | None = None
        self._rgba = b""
        self._width = 0
        self._height = 0
        self._extracted = b""
        self._gif_buffer: QBuffer | None = None
        self._gif_reader: QImageReader | None = None
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
        self.tabs.addTab(self._build_repair(), "图片修复")
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
        self.lsb_channel.addItems(["R", "G", "B", "A"])
        bar.addWidget(self.lsb_channel)
        bar.addWidget(QLabel("位:"))
        self.lsb_bit = QComboBox()
        self.lsb_bit.addItems([str(i) for i in range(8)])
        bar.addWidget(self.lsb_bit)
        self.btn_bitplane = QPushButton("显示位平面")
        self.btn_bitplane.clicked.connect(self._on_bitplane)
        bar.addWidget(self.btn_bitplane)
        self.btn_extract = QPushButton("提取 LSB 数据")
        self.btn_extract.clicked.connect(self._on_extract)
        bar.addWidget(self.btn_extract)
        bar.addStretch()
        layout.addLayout(bar)

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
        layout.addWidget(self.lsb_output, 1)
        return page

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
        layout.addWidget(self.repair_log, 1)
        return page

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
        self.frame_combo.currentIndexChanged.connect(self._show_frame)
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
            QMessageBox.warning(self, "MiscKit", f"读取文件失败:{e}")
            return
        self._path = path
        self._data = data
        self._kind = identify(data, os.path.basename(path)).real_name
        self.file_label.setText(f"{self._path}  ({len(data):,} 字节)  |  {self._kind}")
        self._load_image()
        self._refresh_info()
        self._refresh_repair()
        self._refresh_exif()
        self._refresh_frames()
        self.btn_bitplane.setEnabled(bool(self._rgba))
        self.btn_extract.setEnabled(bool(self._rgba))
        self.lsb_preview.setText("位平面预览")
        self.lsb_preview.setPixmap(QPixmap())
        self.lsb_output.setPlainText("")
        self._extracted = b""

    def _load_image(self) -> None:
        self._image = QImage.fromData(self._data) if self._data else None
        if self._image is None or self._image.isNull():
            self._image = None
            self._rgba = b""
            self._width = self._height = 0
            self.preview.setPixmap(QPixmap())
            self.preview.setText("无法预览该图片")
            self._update_preview()
            return
        self._width = self._image.width()
        self._height = self._image.height()
        rgba = self._image.convertToFormat(QImage.Format_RGBA8888)
        raw = bytes(rgba.constBits())
        stride = rgba.bytesPerLine()
        row_bytes = self._width * 4
        if stride == row_bytes:
            self._rgba = raw[:self._width * self._height * 4]
        else:
            self._rgba = b"".join(raw[y * stride:y * stride + row_bytes]
                                  for y in range(self._height))
        self._update_preview()

    def _update_preview(self) -> None:
        if self._image is None:
            return
        self.preview.setPixmap(_scaled_pixmap(self._image, self.preview))

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._update_preview()

    # ---------------- 基本信息 ----------------
    def _refresh_info(self) -> None:
        rows = fileparse.image_info(self._kind, self._data)
        if self._width:
            rows.append(("像素总数", f"{self._width * self._height:,}"))
        if not rows:
            rows = [("提示", "该格式暂不支持基本信息解析")]
        _fill_table(self.info_table, rows)
        self.lsb_capacity.setText(
            f"单通道最低位容量:{self._width * self._height // 8:,} 字节"
            if self._width else "单通道最低位容量:—")

    # ---------------- LSB ----------------
    def _on_bitplane(self) -> None:
        if not self._rgba:
            return
        channel = self.lsb_channel.currentIndex()
        bit = self.lsb_bit.currentIndex()
        plane = lsb.bit_plane(self._rgba, 4, channel, bit)
        image = QImage(plane, self._width, self._height,
                       self._width, QImage.Format_Grayscale8).copy()
        self.lsb_preview.setPixmap(_scaled_pixmap(image, self.lsb_preview))

    def _on_extract(self) -> None:
        if not self._rgba:
            return
        channel = self.lsb_channel.currentIndex()
        bit = self.lsb_bit.currentIndex()
        self._extracted = lsb.extract_bytes(self._rgba, 4, channel, bit)
        text = lsb.preview(self._extracted)
        self.lsb_output.setPlainText(
            f"通道 {self.lsb_channel.currentText()} / 第 {bit} 位\n\n{text}")

    def _on_save_lsb(self) -> None:
        if not self._extracted:
            QMessageBox.information(self, "MiscKit", "请先提取 LSB 数据")
            return
        base = os.path.splitext(self._path)[0] or "lsb"
        path, _ = QFileDialog.getSaveFileName(self, "保存提取数据", base + "_lsb.bin")
        if not path:
            return
        try:
            with open(path, "wb") as f:
                f.write(self._extracted)
        except OSError as e:
            QMessageBox.warning(self, "MiscKit", f"保存失败:{e}")
            return
        QMessageBox.information(self, "MiscKit", f"已保存 {len(self._extracted):,} 字节:\n{path}")

    # ---------------- PNG 修复 ----------------
    def _refresh_repair(self) -> None:
        self.crc_table.setRowCount(0)
        self.repair_log.setPlainText("")
        info = fileparse.png_info(self._data) if self._kind == "PNG" else None
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
        rows = [(c.name, f"0x{c.offset:X}", f"{c.stored_crc:08X}", f"{c.calc_crc:08X}")
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
        actual = fileparse.png_actual_size(self._data) if is_png else None
        if actual:
            if actual != (info.width, info.height):
                self._log(f"⚠ IDAT 推算出的实际像素尺寸为 {actual[0]} x {actual[1]},"
                          f"与 IHDR 不符(常见于宽高被篡改)")
            else:
                self._log(f"IDAT 推算尺寸 {actual[0]} x {actual[1]},与 IHDR 一致")

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
                f.write(data)
        except OSError as e:
            QMessageBox.warning(self, "MiscKit", f"保存失败:{e}")
            return None
        return path

    def _on_fix_crc(self) -> None:
        info = fileparse.png_info(self._data)
        if info is None:
            return
        if not info.crc_errors:
            QMessageBox.information(self, "MiscKit", "所有 chunk 的 CRC 均正确,无需修复")
            return
        fixed = fileparse.repair_png_crc(self._data)
        path = self._save_bytes(fixed, "crcfix")
        if not path:
            return
        self._log(f"✓ 已修复 {len(info.crc_errors)} 个 CRC 并保存:{path}")
        QMessageBox.information(self, "MiscKit", f"CRC 修复完成:\n{path}")

    def _on_fix_size(self) -> None:
        if self._kind != "PNG":
            return
        width, height = self.spin_width.value(), self.spin_height.value()
        fixed = fileparse.repair_png_dimensions(self._data, width, height)
        path = self._save_bytes(fixed, f"{width}x{height}")
        if not path:
            return
        self._log(f"✓ 已将 IHDR 改为 {width} x {height} 并重算 CRC:{path}")
        QMessageBox.information(self, "MiscKit", f"宽高修复完成:\n{path}")

    def _on_auto_size(self) -> None:
        info = fileparse.png_info(self._data)
        actual = fileparse.png_actual_size(self._data)
        if info is None or actual is None:
            QMessageBox.warning(self, "MiscKit", "无法从 IDAT 推算尺寸(可能已截断或为隔行 PNG)")
            return
        if actual == (info.width, info.height):
            QMessageBox.information(
                self, "MiscKit",
                f"IHDR 与 IDAT 推算一致({actual[0]} x {actual[1]}),无需修复")
            return
        self.spin_width.setValue(actual[0])
        self.spin_height.setValue(actual[1])
        fixed = fileparse.repair_png_dimensions(self._data, actual[0], actual[1])
        path = self._save_bytes(fixed, f"{actual[0]}x{actual[1]}")
        if not path:
            return
        self._log(f"✓ 已按 IDAT 推算尺寸 {actual[0]} x {actual[1]} 修复:{path}")
        QMessageBox.information(self, "MiscKit", f"宽高自动修复完成:\n{path}")

    # ---------------- EXIF ----------------
    def _refresh_exif(self) -> None:
        rows = fileparse.parse_exif(self._data)
        if not rows:
            rows = [("提示", "未发现 EXIF 数据(仅支持 JPEG APP1)")]
        _fill_table(self.exif_table, rows)

    # ---------------- GIF 帧 ----------------
    def _refresh_frames(self) -> None:
        self.frame_combo.blockSignals(True)
        self.frame_combo.clear()
        self._gif_reader = None
        self._gif_buffer = None
        if self._kind != "GIF":
            self.frame_combo.addItem("仅 GIF 支持逐帧查看")
            self.frame_combo.setEnabled(False)
            self.frame_preview.setPixmap(QPixmap())
            self.frame_preview.setText("仅 GIF 支持逐帧查看")
            self.frame_combo.blockSignals(False)
            return
        buffer = QBuffer()
        buffer.setData(self._data)
        buffer.open(QIODevice.ReadOnly)
        reader = QImageReader(buffer)
        count = reader.imageCount()
        self._gif_buffer = buffer
        self._gif_reader = reader
        self.frame_combo.setEnabled(True)
        if count <= 0:
            self.frame_combo.addItem("无法读取帧")
            self.frame_combo.blockSignals(False)
            return
        for i in range(count):
            self.frame_combo.addItem(f"第 {i + 1} 帧")
        self.frame_combo.blockSignals(False)
        self.frame_combo.setCurrentIndex(0)
        self._show_frame(0)

    def _show_frame(self, index: int) -> None:
        if self._gif_reader is None or index < 0:
            return
        reader = self._gif_reader
        if index > 0 and not reader.jumpToImage(index):
            return
        image = reader.read()
        if image.isNull():
            self.frame_preview.setPixmap(QPixmap())
            self.frame_preview.setText("无法读取该帧")
            return
        self.frame_preview.setPixmap(_scaled_pixmap(image, self.frame_preview))
