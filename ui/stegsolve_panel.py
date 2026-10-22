"""StegSolve 风格工具:Data Extract / Image Combiner / Stereogram / Random Color Map."""

from __future__ import annotations

import os

from PySide6.QtCore import Qt
from PySide6.QtGui import QImage, QPixmap
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core import imagetools, lsb, stegsolve
from ui.highlight import install_flag_highlighter


def _scaled(image: QImage, label: QLabel) -> QPixmap:
    pixmap = QPixmap.fromImage(image)
    size = label.size()
    if size.width() > 16 and size.height() > 16:
        pixmap = pixmap.scaled(size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
    return pixmap


class StegSolvePanel(QWidget):
    """集中放置 StegSolve 中适合纯 Python 实现的功能。"""

    CHANNEL_NAMES = ("R", "G", "B", "A")

    def __init__(self) -> None:
        super().__init__()
        self._image: QImage | None = None
        self._pixels = b""
        self._width = 0
        self._height = 0
        self._extracted = b""
        self._result_image: QImage | None = None
        self._build_ui()
        self.set_image(None)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_extract(), "Data Extract")
        self.tabs.addTab(self._build_combiner(), "Image Combiner")
        self.tabs.addTab(self._build_stereogram(), "Stereogram")
        self.tabs.addTab(self._build_color_map(), "Random Color Map")
        layout.addWidget(self.tabs)

    # ---------------- Data Extract ----------------
    def _build_extract(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(QLabel("勾选每个通道要提取的 bit 平面:"))

        grid = QGridLayout()
        grid.addWidget(QLabel("通道"), 0, 0)
        for bit in range(8):
            grid.addWidget(QLabel(str(bit)), 0, bit + 1)
        self._bit_checks: dict[tuple[int, int], QCheckBox] = {}
        for row, name in enumerate(self.CHANNEL_NAMES):
            grid.addWidget(QLabel(name), row + 1, 0)
            for bit in range(8):
                check = QCheckBox()
                check.setChecked(name == "R" and bit == 0)
                grid.addWidget(check, row + 1, bit + 1)
                self._bit_checks[(row, bit)] = check
        layout.addLayout(grid)

        opts = QHBoxLayout()
        opts.addWidget(QLabel("通道顺序:"))
        self.channel_order = QComboBox()
        for label, value in (
            ("RGB", (0, 1, 2)), ("RBG", (0, 2, 1)),
            ("GRB", (1, 0, 2)), ("GBR", (1, 2, 0)),
            ("BRG", (2, 0, 1)), ("BGR", (2, 1, 0)),
            ("RGBA", (0, 1, 2, 3)), ("BGRA", (2, 1, 0, 3)),
        ):
            self.channel_order.addItem(label, value)
        opts.addWidget(self.channel_order)
        opts.addWidget(QLabel("位序:"))
        self.bit_order = QComboBox()
        self.bit_order.addItem("MSB first", "msb")
        self.bit_order.addItem("LSB first", "lsb")
        opts.addWidget(self.bit_order)
        opts.addWidget(QLabel("bit 平面顺序:"))
        self.plane_order = QComboBox()
        self.plane_order.addItem("低位→高位", "low")
        self.plane_order.addItem("高位→低位", "high")
        opts.addWidget(self.plane_order)
        opts.addWidget(QLabel("最多字节:"))
        self.max_bytes = QSpinBox()
        self.max_bytes.setRange(0, 2 ** 31 - 1)
        self.max_bytes.setSpecialValueText("全部")
        opts.addWidget(self.max_bytes)
        self.btn_extract = QPushButton("提取")
        self.btn_extract.clicked.connect(self._on_extract)
        opts.addWidget(self.btn_extract)
        self.btn_save_extract = QPushButton("保存…")
        self.btn_save_extract.clicked.connect(self._on_save_extract)
        self.btn_save_extract.setEnabled(False)
        opts.addWidget(self.btn_save_extract)
        opts.addStretch()
        layout.addLayout(opts)

        self.extract_preview = QLabel("选择 bit 平面后点击提取")
        self.extract_preview.setAlignment(Qt.AlignCenter)
        self.extract_preview.setMinimumHeight(100)
        self.extract_preview.setStyleSheet("background:#1b1b1b;color:#888;")
        layout.addWidget(self.extract_preview, 1)
        self.extract_output = QPlainTextEdit()
        self.extract_output.setReadOnly(True)
        self.extract_output.setPlaceholderText("提取结果(文本/Hex)")
        install_flag_highlighter(self.extract_output)
        layout.addWidget(self.extract_output, 1)
        return page

    def _selected_bits(self) -> dict[int, set[int]]:
        selected: dict[int, set[int]] = {}
        for (channel, bit), check in self._bit_checks.items():
            if check.isChecked():
                selected.setdefault(channel, set()).add(bit)
        return selected

    def _on_extract(self) -> None:
        if not self._pixels:
            return
        selected = self._selected_bits()
        if not selected:
            QMessageBox.information(self, "MiscKit", "请至少勾选一个 bit 平面")
            return
        order = self.channel_order.currentData() or (0, 1, 2)
        self._extracted = stegsolve.extract_selected(
            self._pixels, 4, selected, order,
            bit_order=self.bit_order.currentData() or "msb",
            plane_order=self.plane_order.currentData() or "low",
            max_bytes=self.max_bytes.value(),
        )
        self.extract_output.setPlainText(lsb.preview(self._extracted))
        self.btn_save_extract.setEnabled(bool(self._extracted))
        first_channel = next(iter(selected))
        first_bit = min(selected[first_channel])
        plane = lsb.bit_plane(self._pixels, 4, first_channel, first_bit)
        image = QImage(plane, self._width, self._height,
                       self._width, QImage.Format_Grayscale8).copy()
        self.extract_preview.setPixmap(_scaled(image, self.extract_preview))

    def _on_save_extract(self) -> None:
        if not self._extracted:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "保存 Data Extract 结果", "stegsolve_extract.bin")
        if not path:
            return
        try:
            with open(path, "wb") as f:
                f.write(self._extracted)
        except OSError as e:
            QMessageBox.warning(self, "MiscKit", f"保存失败:{e}")
            return
        QMessageBox.information(self, "MiscKit", f"已保存 {len(self._extracted):,} 字节")

    # ---------------- Image Combiner ----------------
    def _build_combiner(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("运算:"))
        self.combine_op = QComboBox()
        for label, value in (
            ("XOR", "xor"), ("ADD", "add"), ("SUB", "sub"),
            ("AND", "and"), ("OR", "or"), ("MIN", "min"),
            ("MAX", "max"), ("DIFF", "diff"),
        ):
            self.combine_op.addItem(label, value)
        bar.addWidget(self.combine_op)
        self.btn_choose_other = QPushButton("选择另一张图…")
        self.btn_choose_other.clicked.connect(self._on_combine)
        bar.addWidget(self.btn_choose_other)
        self.btn_save_combine = QPushButton("保存结果…")
        self.btn_save_combine.clicked.connect(self._on_save_result)
        self.btn_save_combine.setEnabled(False)
        bar.addWidget(self.btn_save_combine)
        bar.addStretch()
        layout.addLayout(bar)
        self.combine_preview = QLabel("XOR / ADD / SUB / AND / OR / MIN / MAX / DIFF")
        self.combine_preview.setAlignment(Qt.AlignCenter)
        self.combine_preview.setStyleSheet("background:#1b1b1b;color:#888;")
        layout.addWidget(self.combine_preview, 1)
        return page

    def _other_image(self) -> QImage | None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择另一张图", "",
            "图片 (*.png *.jpg *.jpeg *.bmp *.gif *.webp *.tif *.tiff)")
        if not path:
            return None
        image = QImage(path)
        if image.isNull():
            QMessageBox.warning(self, "MiscKit", "无法解码该图片")
            return None
        return image

    def _on_combine(self) -> None:
        if self._image is None:
            return
        other = self._other_image()
        if other is None:
            return
        result = imagetools.combine(
            self._image, other, self.combine_op.currentData() or "xor")
        if result is None:
            QMessageBox.warning(self, "MiscKit", "两张图片尺寸必须相同")
            return
        self._set_result(result, self.combine_preview, self.btn_save_combine)

    # ---------------- Stereogram ----------------
    def _build_stereogram(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("最小偏移:"))
        self.min_offset = QSpinBox()
        self.min_offset.setRange(1, 500)
        self.min_offset.setValue(5)
        bar.addWidget(self.min_offset)
        bar.addWidget(QLabel("最大偏移:"))
        self.max_offset = QSpinBox()
        self.max_offset.setRange(2, 500)
        self.max_offset.setValue(60)
        bar.addWidget(self.max_offset)
        self.btn_stereo = QPushButton("解 Stereogram")
        self.btn_stereo.clicked.connect(self._on_stereogram)
        bar.addWidget(self.btn_stereo)
        self.btn_save_stereo = QPushButton("保存结果…")
        self.btn_save_stereo.clicked.connect(self._on_save_result)
        self.btn_save_stereo.setEnabled(False)
        bar.addWidget(self.btn_save_stereo)
        bar.addStretch()
        layout.addLayout(bar)
        self.stereo_preview = QLabel("自动立体图深度图")
        self.stereo_preview.setAlignment(Qt.AlignCenter)
        self.stereo_preview.setStyleSheet("background:#1b1b1b;color:#888;")
        layout.addWidget(self.stereo_preview, 1)
        return page

    def _on_stereogram(self) -> None:
        if self._image is None:
            return
        result = imagetools.stereogram(
            self._image, self.min_offset.value(), self.max_offset.value())
        if result is None:
            QMessageBox.warning(self, "MiscKit", "图片尺寸过小,无法计算")
            return
        self._set_result(result, self.stereo_preview, self.btn_save_stereo)

    # ---------------- Random Color Map ----------------
    def _build_color_map(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("随机种子:"))
        self.seed_spin = QSpinBox()
        self.seed_spin.setRange(0, 2 ** 31 - 1)
        bar.addWidget(self.seed_spin)
        self.btn_color_map = QPushButton("生成随机颜色映射")
        self.btn_color_map.clicked.connect(self._on_color_map)
        bar.addWidget(self.btn_color_map)
        self.btn_save_map = QPushButton("保存结果…")
        self.btn_save_map.clicked.connect(self._on_save_result)
        self.btn_save_map.setEnabled(False)
        bar.addWidget(self.btn_save_map)
        bar.addStretch()
        layout.addLayout(bar)
        self.map_preview = QLabel("同色像素映射为同一随机色,用于打乱调色板看轮廓")
        self.map_preview.setAlignment(Qt.AlignCenter)
        self.map_preview.setStyleSheet("background:#1b1b1b;color:#888;")
        layout.addWidget(self.map_preview, 1)
        return page

    def _on_color_map(self) -> None:
        if self._image is None:
            return
        self._set_result(
            imagetools.random_color_map(self._image, self.seed_spin.value()),
            self.map_preview, self.btn_save_map)

    # ---------------- 公共 ----------------
    def _set_result(self, image: QImage, label: QLabel,
                    button: QPushButton) -> None:
        self._result_image = image
        label.setPixmap(_scaled(image, label))
        button.setEnabled(True)

    def _on_save_result(self) -> None:
        if self._result_image is None:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "保存 StegSolve 结果", "stegsolve_result.png", "PNG (*.png)")
        if not path:
            return
        if not self._result_image.save(path, "PNG"):
            QMessageBox.warning(self, "MiscKit", "保存失败")
            return
        QMessageBox.information(self, "MiscKit", f"已保存:\n{path}")

    def set_image(self, image: QImage | None) -> None:
        self._image = image
        self._pixels = b""
        self._width = self._height = 0
        self._extracted = b""
        self._result_image = None
        for button in (self.btn_extract, self.btn_choose_other, self.btn_stereo,
                       self.btn_color_map):
            button.setEnabled(image is not None)
        for button in (self.btn_save_combine, self.btn_save_stereo,
                       self.btn_save_map):
            button.setEnabled(False)
        if image is None:
            return
        self._pixels, self._width, self._height = imagetools.rgba_data(image)
        self.extract_output.clear()
        self.extract_preview.setPixmap(QPixmap())
        self.extract_preview.setText("选择 bit 平面后点击提取")
        self.combine_preview.setPixmap(QPixmap())
        self.combine_preview.setText("XOR / ADD / SUB / AND / OR / MIN / MAX / DIFF")
        self.stereo_preview.setPixmap(QPixmap())
        self.stereo_preview.setText("自动立体图深度图")
        self.map_preview.setPixmap(QPixmap())
        self.map_preview.setText("同色像素映射为同一随机色,用于打乱调色板看轮廓")
        self.btn_save_extract.setEnabled(False)
