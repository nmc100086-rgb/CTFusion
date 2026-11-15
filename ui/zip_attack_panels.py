"""ZIP 额外攻击页签:CRC32 明文反查与 bkcrack 已知明文攻击(KPA)。

两个页签都只接受本地 ZIP,所有耗时操作在 QThread 中执行;bkcrack 通过
core.bkcrack 以固定参数调用,不在 Python 中实现攻击算法。
"""

from __future__ import annotations

import os
import threading
import zlib

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import bkcrack, zipcrack
from ui.highlight import install_flag_highlighter


def _display_text(data: bytes) -> str:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    return "".join(ch if ch.isprintable() else "." for ch in text)


def _parse_hex(text: str) -> bytes:
    cleaned = "".join(ch for ch in text if ch not in " \t\r\n,;:-")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) % 2:
        raise ValueError("Hex 长度必须是偶数")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError("Hex 中包含非法字符") from exc


class CrcBruteWorker(QThread):
    progress = Signal(int, int)
    resultReady = Signal(object)

    def __init__(self, data: bytes, entry_index: int) -> None:
        super().__init__()
        self.data = data
        self.entry_index = entry_index
        self.cancel_event = threading.Event()

    def run(self) -> None:
        try:
            result = zipcrack.crc32_bruteforce(
                self.data, self.entry_index,
                cancel=self.cancel_event,
                progress=lambda done, total: self.progress.emit(done, total),
            )
        except Exception as exc:  # 防止线程异常导致按钮卡死
            result = zipcrack.CrcBruteResult(
                entry_index=self.entry_index, error=f"CRC 线程异常:{exc}")
        self.resultReady.emit(result)

    def stop(self) -> None:
        self.cancel_event.set()


class CrcAttackPanel(QWidget):
    """CRC32 明文反查页签。"""

    plaintextSelected = Signal(bytes, int)
    MAX_DISPLAY = 1000

    def __init__(self) -> None:
        super().__init__()
        self._path = ""
        self._data = b""
        self._info: zipcrack.ZipInspect | None = None
        self._entries: list[int] = []
        self._candidates: list[bytes] = []
        self._worker: CrcBruteWorker | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        self.info_label = QLabel(
            "仅用于极小的 ZipCrypto 条目:ZIP ≤ 1 MiB、明文 ≤ 6 字节。"
            "CRC32 只有 32 位,通常只能唯一确定 4 字节左右的明文。")
        self.info_label.setWordWrap(True)
        layout.addWidget(self.info_label)

        row = QHBoxLayout()
        row.addWidget(QLabel("加密条目:"))
        self.entry_combo = QComboBox()
        self.entry_combo.currentIndexChanged.connect(self._on_entry_changed)
        row.addWidget(self.entry_combo, 1)
        self.btn_start = QPushButton("开始 CRC 爆破")
        self.btn_start.clicked.connect(self._on_start)
        self.btn_start.setEnabled(False)
        row.addWidget(self.btn_start)
        self.btn_stop = QPushButton("停止")
        self.btn_stop.clicked.connect(self._on_stop)
        self.btn_stop.setEnabled(False)
        row.addWidget(self.btn_stop)
        layout.addLayout(row)

        self.meta_label = QLabel("载入 ZIP 后选择条目。")
        self.meta_label.setWordWrap(True)
        layout.addWidget(self.meta_label)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["#", "明文", "HEX", "说明"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        layout.addWidget(self.table, 1)

        actions = QHBoxLayout()
        self.btn_copy_text = QPushButton("复制选中明文")
        self.btn_copy_text.clicked.connect(self._on_copy_text)
        self.btn_copy_text.setEnabled(False)
        actions.addWidget(self.btn_copy_text)
        self.btn_copy_hex = QPushButton("复制选中 HEX")
        self.btn_copy_hex.clicked.connect(self._on_copy_hex)
        self.btn_copy_hex.setEnabled(False)
        actions.addWidget(self.btn_copy_hex)
        self.btn_to_kpa = QPushButton("导入已知明文攻击 →")
        self.btn_to_kpa.clicked.connect(self._on_to_kpa)
        self.btn_to_kpa.setEnabled(False)
        actions.addWidget(self.btn_to_kpa)
        actions.addStretch()
        layout.addLayout(actions)

        self.status = QLabel("等待开始。")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(2000)
        self.log.setPlaceholderText("CRC 爆破日志")
        install_flag_highlighter(self.log)
        layout.addWidget(self.log, 1)

        self.table.itemSelectionChanged.connect(self._update_actions)

    def set_archive(self, path: str, data: bytes,
                    info: zipcrack.ZipInspect | None) -> None:
        self._stop_worker()
        self._path = path
        self._data = data
        self._info = info
        self._entries = []
        self._candidates = []
        self.table.setRowCount(0)
        self.entry_combo.blockSignals(True)
        self.entry_combo.clear()
        if info is not None and not info.error:
            for index, entry in enumerate(info.entries):
                if (entry.flags & 1 and not entry.aes and not entry.pseudo
                        and not (entry.flags & 0x40)
                        and entry.method in (0, 8)
                        and entry.size <= zipcrack.MAX_CRC_ENTRY_BYTES):
                    self._entries.append(index)
                    label = (
                        f"[{index}] {entry.name}  "
                        f"{entry.size}B  CRC={entry.crc:08X}")
                    self.entry_combo.addItem(label, index)
        self.entry_combo.blockSignals(False)
        if self._entries:
            self.entry_combo.setCurrentIndex(0)
        self._on_entry_changed()

    def clear(self) -> bool:
        self._stop_worker()
        self._path = ""
        self._data = b""
        self._info = None
        self._entries = []
        self._candidates = []
        self.table.setRowCount(0)
        self.entry_combo.clear()
        self.meta_label.setText("载入 ZIP 后选择条目。")
        self.status.setText("等待开始。")
        self.log.clear()
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(False)
        self._update_actions()
        return True

    def _current_entry(self) -> zipcrack.ZipEntry | None:
        if self._info is None:
            return None
        index = self.entry_combo.currentData()
        if index is None or not (0 <= int(index) < len(self._info.entries)):
            return None
        return self._info.entries[int(index)]

    def _on_entry_changed(self) -> None:
        entry = self._current_entry()
        if entry is None:
            self.meta_label.setText(
                "没有可爆破的条目。只列出已加密、非 AES、非伪加密、"
                f"明文 ≤ {zipcrack.MAX_CRC_ENTRY_BYTES} 字节的条目。")
            self.btn_start.setEnabled(False)
            return
        method = {0: "存储", 8: "Deflate"}.get(entry.method, str(entry.method))
        self.meta_label.setText(
            f"条目:{entry.name}\n"
            f"CRC32 = {entry.crc:08X}    明文大小 = {entry.size} 字节    "
            f"压缩方法 = {method}    加密后大小 = {entry.compressed_size} 字节\n"
            f"候选空间 = 2^{max(0, entry.size * 8 - 32)}"
            f"(最多 {zipcrack.MAX_CRC_SOLUTIONS:,})")
        self.btn_start.setEnabled(self._worker is None)

    def _on_start(self) -> None:
        if self._worker is not None:
            return
        entry = self._current_entry()
        index = self.entry_combo.currentData()
        if entry is None or index is None:
            return
        self._candidates = []
        self.table.setRowCount(0)
        self.log.clear()
        self.status.setText("正在枚举 CRC32 候选…")
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        worker = CrcBruteWorker(self._data, int(index))
        worker.progress.connect(self._on_progress)
        worker.resultReady.connect(self._on_result)
        worker.finished.connect(self._on_finished)
        self._worker = worker
        worker.start()

    def _on_stop(self) -> None:
        if self._worker is not None:
            self._worker.stop()
            self.btn_stop.setEnabled(False)
            self.status.setText("正在停止…")

    def _on_progress(self, done: int, total: int) -> None:
        self.status.setText(f"已枚举 {done:,} / {total:,} 个候选…")

    def _on_result(self, result: zipcrack.CrcBruteResult) -> None:
        if result.cancelled:
            self.status.setText(f"已停止,已枚举 {result.tried:,} 个候选")
            self.log.appendPlainText(f"已停止,已枚举 {result.tried:,} 个候选")
            return
        if result.error:
            self.status.setText("CRC 爆破失败:" + result.error)
            self.log.appendPlainText("⚠ " + result.error)
            return
        self._candidates = result.candidates
        shown = result.candidates[:self.MAX_DISPLAY]
        self.table.setRowCount(len(shown))
        for row, data in enumerate(shown):
            values = [
                str(row + 1),
                _display_text(data),
                data.hex(" ").upper(),
                f"{len(data)} 字节",
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 0:
                    item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row, col, item)
        if not result.candidates:
            entry = self._current_entry()
            crc_text = f" CRC={entry.crc:08X}" if entry is not None else ""
            self.status.setText(
                f"没有找到匹配{crc_text} 的明文;"
                "CRC 可能被伪造,或条目并非 ZipCrypto。")
            self.log.appendPlainText(
                f"已枚举 {result.tried:,} 个候选,没有匹配项。")
            return
        extra = ""
        if len(result.candidates) > len(shown):
            extra = f"(仅显示前 {len(shown)} 条)"
        self.status.setText(
            f"✓ 找到 {len(result.candidates):,} 个候选{extra},"
            f"耗时 {result.elapsed:.2f}s。")
        self.log.appendPlainText(
            f"✓ CRC32 反查完成:候选 {len(result.candidates):,} 个,"
            f"枚举 {result.tried:,} 个,耗时 {result.elapsed:.2f}s。")
        self.log.appendPlainText(
            "提示:CRC 只能确定明文内容;若要用于 bkcrack,"
            "还需要至少 8 字节连续明文和总计 12 字节已知字节。")

    def _on_finished(self) -> None:
        self._worker = None
        self.btn_stop.setEnabled(False)
        self.btn_start.setEnabled(self._current_entry() is not None)
        self._update_actions()

    def _selected_data(self) -> bytes | None:
        row = self.table.currentRow()
        if 0 <= row < len(self._candidates):
            return self._candidates[row]
        return None

    def _update_actions(self) -> None:
        enabled = self._selected_data() is not None
        self.btn_copy_text.setEnabled(enabled)
        self.btn_copy_hex.setEnabled(enabled)
        self.btn_to_kpa.setEnabled(enabled)

    def _on_copy_text(self) -> None:
        data = self._selected_data()
        if data is None:
            return
        QGuiApplication.clipboard().setText(_display_text(data))
        self.status.setText("明文已复制到剪贴板")

    def _on_copy_hex(self) -> None:
        data = self._selected_data()
        if data is None:
            return
        QGuiApplication.clipboard().setText(data.hex(" ").upper())
        self.status.setText("HEX 已复制到剪贴板")

    def _on_to_kpa(self) -> None:
        data = self._selected_data()
        if data is None:
            return
        self.plaintextSelected.emit(data, 0)
        self.status.setText(
            "已导入已知明文攻击页;可在 HEX 后追加已知字节,"
            "使连续明文 ≥8 字节、总计 ≥12 字节。")

    def _stop_worker(self, timeout_ms: int = 3000) -> bool:
        worker = self._worker
        if worker is None:
            return True
        worker.stop()
        if worker.isRunning() and not worker.wait(timeout_ms):
            return False
        self._worker = None
        self.btn_stop.setEnabled(False)
        self.btn_start.setEnabled(self._current_entry() is not None)
        return True

    def shutdown(self) -> bool:
        return self._stop_worker()


class KpaWorker(QThread):
    output = Signal(str)
    resultReady = Signal(object)

    def __init__(self, config: bkcrack.KpaConfig) -> None:
        super().__init__()
        self.config = config
        self.cancel_event = threading.Event()

    def run(self) -> None:
        try:
            result = bkcrack.attack(
                self.config,
                on_output=self.output.emit,
                cancel=self.cancel_event,
            )
        except Exception as exc:
            result = bkcrack.KpaResult(error=f"KPA 线程异常:{exc}")
        self.resultReady.emit(result)

    def stop(self) -> None:
        self.cancel_event.set()


class KpaAttackPanel(QWidget):
    """bkcrack 已知明文攻击页签。"""

    def __init__(self) -> None:
        super().__init__()
        self._path = ""
        self._data = b""
        self._info: zipcrack.ZipInspect | None = None
        self._keys: tuple[int, int, int] | None = None
        self._worker: KpaWorker | None = None
        self._build_ui()
        self._show_info()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        self.info_label = QLabel()
        self.info_label.setWordWrap(True)
        layout.addWidget(self.info_label)

        row = QHBoxLayout()
        row.addWidget(QLabel("加密条目:"))
        self.entry_combo = QComboBox()
        self.entry_combo.currentIndexChanged.connect(self._on_entry_changed)
        row.addWidget(self.entry_combo, 1)
        layout.addLayout(row)

        self.entry_meta = QLabel("载入 ZIP 后选择条目。")
        self.entry_meta.setWordWrap(True)
        layout.addWidget(self.entry_meta)

        source_group = QGroupBox("已知明文")
        source_layout = QVBoxLayout(source_group)
        source_row = QHBoxLayout()
        self.rb_file = QRadioButton("明文文件")
        self.rb_hex = QRadioButton("HEX / 文本")
        self.source_group = QButtonGroup(self)
        self.source_group.addButton(self.rb_file)
        self.source_group.addButton(self.rb_hex)
        self.rb_file.setChecked(True)
        source_row.addWidget(self.rb_file)
        self.plain_edit = QLineEdit()
        self.plain_edit.setPlaceholderText("选择已知明文文件")
        source_row.addWidget(self.plain_edit, 1)
        self.btn_browse = QPushButton("浏览…")
        self.btn_browse.clicked.connect(self._choose_plaintext)
        source_row.addWidget(self.btn_browse)
        source_layout.addLayout(source_row)

        source_row2 = QHBoxLayout()
        source_row2.addWidget(self.rb_hex)
        self.hex_mode = QComboBox()
        self.hex_mode.addItem("HEX", "hex")
        self.hex_mode.addItem("UTF-8 文本", "text")
        source_row2.addWidget(self.hex_mode)
        source_row2.addStretch()
        source_layout.addLayout(source_row2)
        self.hex_edit = QPlainTextEdit()
        self.hex_edit.setPlaceholderText(
            "粘贴 HEX(可带空格)或文本;CRC 爆破结果可直接导入此处")
        self.hex_edit.setMaximumHeight(90)
        source_layout.addWidget(self.hex_edit)

        options = QHBoxLayout()
        options.addWidget(QLabel("明文偏移:"))
        self.offset_spin = QSpinBox()
        self.offset_spin.setRange(0, 0x7FFFFFFF)
        self.offset_spin.setToolTip(
            "已知明文在压缩数据中的偏移(不含 12 字节 ZipCrypto 头)")
        options.addWidget(self.offset_spin)
        self.deflate_check = QCheckBox("明文是原始文件内容,先按 Deflate 压缩")
        self.deflate_check.toggled.connect(self._on_deflate_toggled)
        options.addWidget(self.deflate_check)
        options.addWidget(QLabel("级别:"))
        self.deflate_level = QComboBox()
        self.deflate_level.addItem("默认 6", 6)
        for level in (1, 2, 3, 4, 5, 7, 8, 9):
            self.deflate_level.addItem(str(level), level)
        options.addWidget(self.deflate_level)
        options.addStretch()
        source_layout.addLayout(options)
        layout.addWidget(source_group)

        extra_group = QGroupBox("额外已知字节(可选,对应 bkcrack -x)")
        extra_layout = QVBoxLayout(extra_group)
        self.extra_table = QTableWidget(0, 2)
        self.extra_table.setHorizontalHeaderLabels(["偏移", "HEX"])
        self.extra_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeToContents)
        self.extra_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.Stretch)
        self.extra_table.verticalHeader().setVisible(False)
        extra_layout.addWidget(self.extra_table)
        extra_buttons = QHBoxLayout()
        self.btn_add_extra = QPushButton("添加一行")
        self.btn_add_extra.clicked.connect(self._add_extra_row)
        extra_buttons.addWidget(self.btn_add_extra)
        self.btn_remove_extra = QPushButton("删除选中")
        self.btn_remove_extra.clicked.connect(self._remove_extra_row)
        extra_buttons.addWidget(self.btn_remove_extra)
        extra_buttons.addStretch()
        extra_layout.addLayout(extra_buttons)
        layout.addWidget(extra_group)

        actions = QHBoxLayout()
        self.btn_start = QPushButton("开始已知明文攻击")
        self.btn_start.clicked.connect(self._on_start)
        self.btn_start.setEnabled(False)
        actions.addWidget(self.btn_start)
        self.btn_stop = QPushButton("停止")
        self.btn_stop.clicked.connect(self._on_stop)
        self.btn_stop.setEnabled(False)
        actions.addWidget(self.btn_stop)
        self.btn_copy_keys = QPushButton("复制密钥")
        self.btn_copy_keys.clicked.connect(self._on_copy_keys)
        self.btn_copy_keys.setEnabled(False)
        actions.addWidget(self.btn_copy_keys)
        self.btn_decrypt = QPushButton("解密当前条目…")
        self.btn_decrypt.clicked.connect(self._on_decrypt)
        self.btn_decrypt.setEnabled(False)
        actions.addWidget(self.btn_decrypt)
        self.btn_remove = QPushButton("移除密码另存…")
        self.btn_remove.clicked.connect(self._on_remove_password)
        self.btn_remove.setEnabled(False)
        actions.addWidget(self.btn_remove)
        self.btn_change = QPushButton("修改密码另存…")
        self.btn_change.clicked.connect(self._on_change_password)
        self.btn_change.setEnabled(False)
        actions.addWidget(self.btn_change)
        actions.addStretch()
        layout.addLayout(actions)

        self.keys_label = QLabel("密钥:—")
        self.keys_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.keys_label)
        self.status = QLabel("载入 ZIP 并选择加密条目。")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(3000)
        self.log.setPlaceholderText("bkcrack 输出")
        install_flag_highlighter(self.log)
        layout.addWidget(self.log, 1)

    def _show_info(self) -> None:
        info = bkcrack.bkcrack_info()
        if info.available:
            verified = "SHA-256 校验通过" if info.verified else "SHA-256 未匹配(仍可运行)"
            self.info_label.setText(
                f"bkcrack {info.version} · {verified}\n{info.path}")
        else:
            self.info_label.setText(
                "⚠ bkcrack 不可用:" + (info.error or "未知错误"))
        self.info_label.setToolTip(bkcrack.BKCrack_URL)

    def set_archive(self, path: str, data: bytes,
                    info: zipcrack.ZipInspect | None) -> None:
        self._stop_worker()
        if path != self._path:
            self.plain_edit.clear()
            self.hex_edit.clear()
            self.extra_table.setRowCount(0)
        self._path = path
        self._data = data
        self._info = info
        self._keys = None
        self.keys_label.setText("密钥:—")
        self.entry_combo.blockSignals(True)
        self.entry_combo.clear()
        if info is not None and not info.error:
            for index, entry in enumerate(info.entries):
                if (entry.flags & 1 and not entry.aes and not entry.pseudo
                        and not (entry.flags & 0x40)
                        and entry.method in (0, 8)):
                    self.entry_combo.addItem(
                        f"[{index}] {entry.name}  "
                        f"{entry.size}B / {entry.compressed_size}B", index)
        self.entry_combo.blockSignals(False)
        if self.entry_combo.count():
            self.entry_combo.setCurrentIndex(0)
        self._on_entry_changed()
        self._show_info()

    def clear(self) -> bool:
        self._stop_worker()
        self._path = ""
        self._data = b""
        self._info = None
        self._keys = None
        self.entry_combo.clear()
        self.entry_meta.setText("载入 ZIP 后选择条目。")
        self.plain_edit.clear()
        self.hex_edit.clear()
        self.extra_table.setRowCount(0)
        self.keys_label.setText("密钥:—")
        self.status.setText("载入 ZIP 并选择加密条目。")
        self.log.clear()
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(False)
        self._update_key_actions()
        return True

    def _current_entry(self) -> tuple[int, zipcrack.ZipEntry] | None:
        if self._info is None:
            return None
        index = self.entry_combo.currentData()
        if index is None or not (0 <= int(index) < len(self._info.entries)):
            return None
        return int(index), self._info.entries[int(index)]

    def _on_entry_changed(self) -> None:
        current = self._current_entry()
        available = bkcrack.bkcrack_info().available
        if current is None:
            self.entry_meta.setText(
                "没有可攻击的条目;只列出 ZipCrypto 加密、非 AES、非伪加密的"
                "存储/Deflate 条目。")
            self.btn_start.setEnabled(False)
            return
        _index, entry = current
        method = {0: "存储", 8: "Deflate"}.get(entry.method, str(entry.method))
        self.entry_meta.setText(
            f"{entry.name}    方法 {method}    明文 {entry.size} 字节    "
            f"压缩后 {entry.compressed_size} 字节    CRC={entry.crc:08X}")
        self.deflate_check.setEnabled(entry.method == 8)
        if entry.method != 8:
            self.deflate_check.setChecked(False)
        self.btn_start.setEnabled(available and self._worker is None)
        if not available:
            self.status.setText("bkcrack 不可用,请检查 bin/bkcrack.exe")
        elif entry.method == 8:
            self.status.setText(
                "Deflate 条目:已知明文应是压缩后的字节。若你提供的是原始"
                "文件内容,请勾选“先按 Deflate 压缩”。")
        else:
            self.status.setText("存储条目:已知明文直接使用原始字节。")

    def _on_deflate_toggled(self, checked: bool) -> None:
        self.deflate_level.setEnabled(checked)

    def _choose_plaintext(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择已知明文", "", "所有文件 (*)")
        if path:
            self.rb_file.setChecked(True)
            self.plain_edit.setText(path)

    def _add_extra_row(self) -> None:
        row = self.extra_table.rowCount()
        self.extra_table.insertRow(row)
        self.extra_table.setItem(row, 0, QTableWidgetItem("0"))
        self.extra_table.setItem(row, 1, QTableWidgetItem(""))

    def _remove_extra_row(self) -> None:
        row = self.extra_table.currentRow()
        if row >= 0:
            self.extra_table.removeRow(row)

    def _collect_extra(self) -> list[tuple[int, bytes]]:
        result: list[tuple[int, bytes]] = []
        for row in range(self.extra_table.rowCount()):
            offset_item = self.extra_table.item(row, 0)
            hex_item = self.extra_table.item(row, 1)
            offset_text = offset_item.text().strip() if offset_item else ""
            hex_text = hex_item.text().strip() if hex_item else ""
            if not offset_text and not hex_text:
                continue
            try:
                offset = int(offset_text)
            except ValueError as exc:
                raise ValueError(f"第 {row + 1} 行偏移不是整数") from exc
            data = _parse_hex(hex_text)
            if not data:
                raise ValueError(f"第 {row + 1} 行 HEX 为空")
            result.append((offset, data))
        return result

    def _read_plaintext(self) -> bytes:
        if self.rb_hex.isChecked():
            text = self.hex_edit.toPlainText()
            if self.hex_mode.currentData() == "text":
                return text.encode("utf-8")
            return _parse_hex(text)
        path = self.plain_edit.text().strip()
        if not path:
            raise ValueError("请选择已知明文文件")
        if os.path.getsize(path) > bkcrack.MAX_PLAINTEXT_BYTES:
            raise ValueError("已知明文文件超过 64 MB 上限")
        with open(path, "rb") as f:
            return f.read()

    def _on_start(self) -> None:
        if self._worker is not None:
            return
        current = self._current_entry()
        if current is None:
            return
        info = bkcrack.bkcrack_info()
        if not info.available:
            QMessageBox.warning(
                self, "CTFusion",
                info.error or "bkcrack 不可用")
            return
        index, entry = current
        try:
            plaintext = self._read_plaintext()
            extra = self._collect_extra()
            deflate_level = None
            if self.deflate_check.isChecked():
                if entry.method != 8:
                    raise ValueError("只有 Deflate 条目才需要先压缩")
                deflate_level = int(self.deflate_level.currentData() or 6)
            if not plaintext and deflate_level is None:
                raise ValueError("已知明文不能为空")
            config = bkcrack.KpaConfig(
                path=self._path,
                entry_index=index,
                plaintext=plaintext,
                offset=self.offset_spin.value(),
                deflate_level=deflate_level,
                extra=extra,
                data=self._data,
            )
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "CTFusion", str(exc))
            return
        self.log.clear()
        self.keys_label.setText("密钥:—")
        self._keys = None
        self._update_key_actions()
        self.status.setText("正在启动 bkcrack…")
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        worker = KpaWorker(config)
        worker.output.connect(self._on_output)
        worker.resultReady.connect(self._on_result)
        worker.finished.connect(self._on_finished)
        self._worker = worker
        worker.start()

    def _on_stop(self) -> None:
        if self._worker is not None:
            self._worker.stop()
            self.btn_stop.setEnabled(False)
            self.status.setText("正在停止 bkcrack…")

    def _on_output(self, line: str) -> None:
        self.log.appendPlainText(line)

    def _on_result(self, result: bkcrack.KpaResult) -> None:
        if result.success and result.keys is not None:
            self._keys = result.keys
            self.keys_label.setText(
                "密钥:" + " ".join(f"{value:08x}" for value in result.keys))
            self.status.setText(
                f"✓ 已恢复密钥,耗时 {result.elapsed:.2f}s")
            self.log.appendPlainText(
                "✓ Keys = " + " ".join(f"{value:08x}" for value in result.keys))
            QApplication.beep()
        elif result.cancelled:
            self.status.setText("已停止")
        elif result.timed_out:
            self.status.setText("攻击超时")
        else:
            self.status.setText("攻击失败:" + (result.error or "未找到密钥"))
            if result.error:
                self.log.appendPlainText("⚠ " + result.error)
        self._update_key_actions()

    def _on_finished(self) -> None:
        self._worker = None
        self.btn_stop.setEnabled(False)
        available = bkcrack.bkcrack_info().available
        self.btn_start.setEnabled(available and self._current_entry() is not None)

    def _update_key_actions(self) -> None:
        enabled = self._keys is not None
        self.btn_copy_keys.setEnabled(enabled)
        self.btn_decrypt.setEnabled(enabled)
        self.btn_remove.setEnabled(enabled)
        self.btn_change.setEnabled(enabled)

    def _on_copy_keys(self) -> None:
        if self._keys is None:
            return
        text = " ".join(f"{value:08x}" for value in self._keys)
        QGuiApplication.clipboard().setText(text)
        self.status.setText("密钥已复制到剪贴板")

    def receive_plaintext(self, data: bytes, offset: int = 0) -> None:
        self.rb_hex.setChecked(True)
        self.hex_mode.setCurrentIndex(self.hex_mode.findData("hex"))
        self.hex_edit.setPlainText(data.hex(" ").upper())
        self.offset_spin.setValue(max(0, offset))
        current = self._current_entry()
        if current is not None and current[1].method == 8:
            self.deflate_check.setChecked(True)
        if len(data) < bkcrack.MIN_CONTIGUOUS:
            self.status.setText(
                f"已导入 {len(data)} 字节 CRC 明文;bkcrack 需要至少 "
                f"{bkcrack.MIN_CONTIGUOUS} 字节连续明文,"
                "请在 HEX 后追加已知的后续字节。")
        else:
            self.status.setText(
                f"已导入 {len(data)} 字节明文;确认总计至少 "
                f"{bkcrack.MIN_TOTAL_KNOWN} 字节后再开始攻击。")

    def _decrypt_default_name(self, entry: zipcrack.ZipEntry) -> str:
        name = os.path.basename(entry.name.rstrip("/\\")) or "decrypted.bin"
        return name

    def _run_sync(self, title: str, action) -> None:
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            action()
        except Exception as exc:
            QMessageBox.warning(self, "CTFusion", f"{title}失败:{exc}")
        finally:
            QApplication.restoreOverrideCursor()

    def _on_decrypt(self) -> None:
        current = self._current_entry()
        if current is None or self._keys is None:
            return
        index, entry = current
        default = self._decrypt_default_name(entry)
        path, _ = QFileDialog.getSaveFileName(
            self, "保存解密后的条目", default, "所有文件 (*)")
        if not path:
            return

        def action() -> None:
            bkcrack.decrypt_entry(
                self._path, self._data, index, self._keys, path,
                on_output=self._on_output)
            self.log.appendPlainText(f"✓ 已解密条目到:{path}")
            QMessageBox.information(self, "CTFusion", f"已解密:\n{path}")

        self._run_sync("解密", action)

    def _on_remove_password(self) -> None:
        if self._keys is None:
            return
        base = os.path.splitext(self._path)[0] or "archive"
        path, _ = QFileDialog.getSaveFileName(
            self, "移除密码并另存", base + "_unlocked.zip", "ZIP (*.zip)")
        if not path:
            return

        def action() -> None:
            run = bkcrack.remove_password(
                self._path, self._keys, path, on_output=self._on_output)
            if not os.path.isfile(path):
                raise RuntimeError(
                    run.output.splitlines()[-1] if run.output else "未生成输出文件")
            self.log.appendPlainText(f"✓ 已生成无密码 ZIP:{path}")
            QMessageBox.information(
                self, "CTFusion",
                f"已生成无密码副本:\n{path}\n\n"
                "如果原 ZIP 带前置垃圾数据,bkcrack 可能无法整体重建;"
                "可改用“解密当前条目”。")

        self._run_sync("移除密码", action)

    def _on_change_password(self) -> None:
        if self._keys is None:
            return
        password, ok = QInputDialog.getText(
            self, "修改密码", "新密码:", QLineEdit.Password)
        if not ok or not password:
            return
        base = os.path.splitext(self._path)[0] or "archive"
        path, _ = QFileDialog.getSaveFileName(
            self, "修改密码并另存", base + "_newpass.zip", "ZIP (*.zip)")
        if not path:
            return

        def action() -> None:
            run = bkcrack.change_password(
                self._path, self._keys, path, password,
                on_output=self._on_output)
            if not os.path.isfile(path):
                raise RuntimeError(
                    run.output.splitlines()[-1] if run.output else "未生成输出文件")
            self.log.appendPlainText(f"✓ 已生成新密码 ZIP:{path}")
            QMessageBox.information(self, "CTFusion", f"已生成新密码副本:\n{path}")

        self._run_sync("修改密码", action)

    def _stop_worker(self, timeout_ms: int = 4000) -> bool:
        worker = self._worker
        if worker is None:
            return True
        worker.stop()
        if worker.isRunning() and not worker.wait(timeout_ms):
            return False
        self._worker = None
        self.btn_stop.setEnabled(False)
        self.btn_start.setEnabled(
            bkcrack.bkcrack_info().available and self._current_entry() is not None)
        return True

    def shutdown(self) -> bool:
        return self._stop_worker()
