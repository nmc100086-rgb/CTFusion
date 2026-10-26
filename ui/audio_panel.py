"""WAV 音频 LSB 页签:元信息 + 采样位提取。"""

from __future__ import annotations

import os

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
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import audio
from core.filetype import identify
from ui.highlight import install_flag_highlighter


class AudioPanel(QWidget):
    """WAV 元信息与 LSB 提取。"""

    def __init__(self) -> None:
        super().__init__()
        self._path = ""
        self._data = b""
        self._payload = b""
        self._info: audio.WavInfo | None = None
        self._extracted = b""
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        bar = QHBoxLayout()
        self.btn_open = QPushButton("打开 WAV…")
        self.btn_open.clicked.connect(self._choose_file)
        bar.addWidget(self.btn_open)
        self.file_label = QLabel("拖入 WAV 开始分析")
        bar.addWidget(self.file_label, 1)
        layout.addLayout(bar)

        self.info_table = QTableWidget(0, 2)
        self.info_table.setHorizontalHeaderLabels(["项目", "值"])
        self.info_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.info_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.info_table.verticalHeader().setVisible(False)
        self.info_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.info_table.setMaximumHeight(150)
        layout.addWidget(self.info_table)

        opts = QHBoxLayout()
        opts.addWidget(QLabel("通道:"))
        self.channel_combo = QComboBox()
        opts.addWidget(self.channel_combo)
        opts.addWidget(QLabel("位:"))
        self.bit_combo = QComboBox()
        opts.addWidget(self.bit_combo)
        opts.addWidget(QLabel("位序:"))
        self.order_combo = QComboBox()
        self.order_combo.addItem("MSB-first", "msb")
        self.order_combo.addItem("LSB-first", "lsb")
        opts.addWidget(self.order_combo)
        opts.addWidget(QLabel("最多字节:"))
        self.max_spin = QSpinBox()
        self.max_spin.setRange(0, 2 ** 31 - 1)
        self.max_spin.setSpecialValueText("全部")
        opts.addWidget(self.max_spin)
        self.btn_extract = QPushButton("提取 LSB")
        self.btn_extract.clicked.connect(self._on_extract)
        opts.addWidget(self.btn_extract)
        self.btn_save = QPushButton("保存…")
        self.btn_save.clicked.connect(self._on_save)
        self.btn_save.setEnabled(False)
        opts.addWidget(self.btn_save)
        opts.addStretch()
        layout.addLayout(opts)

        self.status = QLabel("WAV LSB:每个采样点取指定 bit")
        layout.addWidget(self.status)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlaceholderText("提取结果")
        install_flag_highlighter(self.output)
        layout.addWidget(self.output, 1)

    def _choose_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "选择 WAV", "", "WAV (*.wav)")
        if path:
            self.load_file(path)

    def load_file(self, path: str) -> bool:
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            QMessageBox.warning(self, "CTFusion", f"读取文件失败:{e}")
            return False
        result = identify(data, os.path.basename(path))
        payload = data[result.prefix:]
        info = audio.read_info(payload)
        if info is None:
            QMessageBox.warning(self, "CTFusion", "不是有效的 WAV/PCM 文件")
            return False
        self._path = path
        self._data = data
        self._payload = payload
        self._info = info
        self._extracted = b""
        label = f"{path}  ({len(data):,} 字节)  |  {result.real_name}"
        if result.prefix:
            label += f"  [前置数据 {result.prefix} 字节]"
        self.file_label.setText(label)
        rows = [
            ("通道数", str(info.channels)),
            ("采样位宽", f"{info.sample_width * 8} bit"),
            ("采样率", f"{info.frame_rate:,} Hz"),
            ("采样帧数", f"{info.frames:,}"),
            ("时长", f"{info.duration:.3f} s"),
            ("单通道最低位容量", f"{info.frames // 8:,} 字节"),
        ]
        self.info_table.setRowCount(len(rows))
        for row, (key, value) in enumerate(rows):
            self.info_table.setItem(row, 0, QTableWidgetItem(key))
            self.info_table.setItem(row, 1, QTableWidgetItem(value))
        self.channel_combo.clear()
        for index in range(info.channels):
            self.channel_combo.addItem(f"通道 {index + 1}", index)
        self.bit_combo.clear()
        for index in range(info.sample_width * 8):
            self.bit_combo.addItem(str(index))
        self.status.setText("选择通道/位后点击提取;flag 会在结果中高亮。")
        self.output.clear()
        self.btn_save.setEnabled(False)
        return True

    def _on_extract(self) -> None:
        if not self._data or self._info is None:
            return
        self._extracted = audio.extract_lsb(
            self._payload,
            channel=self.channel_combo.currentData() or 0,
            bit=self.bit_combo.currentIndex(),
            bit_order=self.order_combo.currentData() or "msb",
            max_bytes=self.max_spin.value(),
        )
        self.output.setPlainText(audio.preview(self._extracted))
        self.status.setText(
            f"通道 {self.channel_combo.currentText()} / 第 {self.bit_combo.currentIndex()} 位 / "
            f"{self.order_combo.currentText()} / 共 {len(self._extracted):,} 字节")
        self.btn_save.setEnabled(bool(self._extracted))

    def _on_save(self) -> None:
        if not self._extracted:
            return
        base = os.path.splitext(self._path)[0] or "wav_lsb"
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
