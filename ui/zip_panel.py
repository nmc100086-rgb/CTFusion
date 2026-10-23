"""ZIP 分析页签:结构 / 伪加密 / 密码恢复 / 安全解压。"""

from __future__ import annotations

import io
import os
import threading
import zipfile

from PySide6.QtCore import QThread, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core import fileparse, zipcrack
from ui.highlight import install_flag_highlighter, mark_item


class CrackWorker(QThread):
    """在后台线程跑密码恢复,避免卡住 Qt 主线程。"""

    progress = Signal("qint64", "qint64", float, str)
    resultReady = Signal(object)

    def __init__(self, config: zipcrack.CrackConfig) -> None:
        super().__init__()
        self.config = config
        self.cancel_event = threading.Event()

    def run(self) -> None:
        try:
            result = zipcrack.recover_zip(
                self.config,
                progress=lambda tried, total, speed, current: self.progress.emit(
                    tried, total, speed, current),
                cancel=self.cancel_event,
            )
        except Exception as e:  # 防止线程静默退出,导致按钮卡死
            result = zipcrack.CrackResult(
                path=self.config.path, error=f"恢复线程异常:{e}")
        self.resultReady.emit(result)

    def stop(self) -> None:
        self.cancel_event.set()


class ZipPanel(QWidget):
    """ZIP 结构查看、伪加密修复、密码恢复与安全解压。"""

    def __init__(self) -> None:
        super().__init__()
        self._path = ""
        self._data = b""
        self._info: zipcrack.ZipInspect | None = None
        self._worker: CrackWorker | None = None
        self._found_password: str | None = None
        self._found_password_bytes = b""
        self._result_received = False
        self._build_ui()
        self.btn_start.setEnabled(False)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        bar = QHBoxLayout()
        self.btn_open = QPushButton("打开 ZIP…")
        self.btn_open.clicked.connect(self._choose_file)
        bar.addWidget(self.btn_open)
        self.file_label = QLabel("拖入 ZIP 文件开始分析")
        bar.addWidget(self.file_label, 1)
        self.btn_extract = QPushButton("安全解压…")
        self.btn_extract.clicked.connect(self._on_extract)
        self.btn_extract.setEnabled(False)
        bar.addWidget(self.btn_extract)
        self.btn_repair = QPushButton("修复伪加密并另存…")
        self.btn_repair.clicked.connect(self._on_repair)
        self.btn_repair.setEnabled(False)
        bar.addWidget(self.btn_repair)
        layout.addLayout(bar)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_structure(), "结构 / 伪加密")
        self.tabs.addTab(self._build_recovery(), "密码恢复")
        layout.addWidget(self.tabs, 1)

    # ---------------- 结构 ----------------
    def _build_structure(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.comment_label = QLabel("压缩包注释:(无)")
        self.comment_label.setWordWrap(True)
        layout.addWidget(self.comment_label)

        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(
            ["文件名", "方法", "原始大小", "压缩后", "CRC32", "加密", "AES", "伪加密"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        for col in range(1, 8):
            self.table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        layout.addWidget(self.table, 1)

        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setPlaceholderText("分析记录")
        install_flag_highlighter(self.log)
        layout.addWidget(self.log)
        return page

    # ---------------- 密码恢复 ----------------
    def _build_recovery(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        top = QHBoxLayout()
        top.addWidget(QLabel("攻击模式:"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItem("字典攻击", "dictionary")
        self.mode_combo.addItem("暴力破解", "brute")
        self.mode_combo.addItem("掩码攻击", "mask")
        self.mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        top.addWidget(self.mode_combo)
        top.addWidget(QLabel("密码编码:"))
        self.encoding_combo = QComboBox()
        for label, value in (("UTF-8", "utf-8"), ("GBK", "gbk"), ("自动", "auto")):
            self.encoding_combo.addItem(label, value)
        top.addWidget(self.encoding_combo)
        top.addStretch()
        self.btn_start = QPushButton("开始恢复")
        self.btn_start.clicked.connect(self._on_start)
        top.addWidget(self.btn_start)
        self.btn_stop = QPushButton("停止")
        self.btn_stop.clicked.connect(self._on_stop)
        self.btn_stop.setEnabled(False)
        top.addWidget(self.btn_stop)
        layout.addLayout(top)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_dictionary_page())
        self.stack.addWidget(self._build_brute_page())
        self.stack.addWidget(self._build_mask_page())
        layout.addWidget(self.stack)

        self.progress = QProgressBar()
        self.progress.setRange(0, 1000)
        self.progress.setValue(0)
        layout.addWidget(self.progress)
        self.status = QLabel("载入 ZIP 后选择模式开始恢复;仅支持 ZipCrypto,不支持 AES。")
        layout.addWidget(self.status)

        result_bar = QHBoxLayout()
        self.result_label = QLabel("密码:—")
        result_bar.addWidget(self.result_label, 1)
        self.btn_copy_pwd = QPushButton("复制密码")
        self.btn_copy_pwd.clicked.connect(self._on_copy_password)
        self.btn_copy_pwd.setEnabled(False)
        result_bar.addWidget(self.btn_copy_pwd)
        layout.addLayout(result_bar)

        self.recovery_log = QPlainTextEdit()
        self.recovery_log.setReadOnly(True)
        self.recovery_log.setPlaceholderText("恢复日志")
        install_flag_highlighter(self.recovery_log)
        layout.addWidget(self.recovery_log, 1)
        return page

    def _build_dictionary_page(self) -> QWidget:
        group = QGroupBox("字典攻击")
        layout = QHBoxLayout(group)
        layout.addWidget(QLabel("字典文件:"))
        self.wordlist_edit = QLineEdit()
        self.wordlist_edit.setPlaceholderText("选择一行一个密码的 txt 字典")
        layout.addWidget(self.wordlist_edit, 1)
        self.btn_wordlist = QPushButton("浏览…")
        self.btn_wordlist.clicked.connect(self._choose_wordlist)
        layout.addWidget(self.btn_wordlist)
        return group

    def _build_brute_page(self) -> QWidget:
        group = QGroupBox("暴力破解")
        layout = QVBoxLayout(group)
        line = QHBoxLayout()
        line.addWidget(QLabel("字符集:"))
        self.charset_edit = QLineEdit("abcdefghijklmnopqrstuvwxyz0123456789")
        line.addWidget(self.charset_edit, 1)
        layout.addLayout(line)
        presets = QHBoxLayout()
        presets.addWidget(QLabel("快捷字符集:"))
        for label, chars in (
            ("小写", "abcdefghijklmnopqrstuvwxyz"),
            ("大写", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
            ("数字", "0123456789"),
            ("小写+数字", "abcdefghijklmnopqrstuvwxyz0123456789"),
            ("全部可打印", "".join(chr(i) for i in range(32, 127))),
        ):
            button = QPushButton(label)
            button.clicked.connect(lambda _=False, c=chars: self._append_charset(c))
            presets.addWidget(button)
        presets.addStretch()
        layout.addLayout(presets)
        length = QHBoxLayout()
        length.addWidget(QLabel("最小长度:"))
        self.min_length = QSpinBox()
        self.min_length.setRange(1, 32)
        self.min_length.setValue(1)
        length.addWidget(self.min_length)
        length.addWidget(QLabel("最大长度:"))
        self.max_length = QSpinBox()
        self.max_length.setRange(1, 32)
        self.max_length.setValue(6)
        length.addWidget(self.max_length)
        length.addStretch()
        layout.addLayout(length)
        return group

    def _build_mask_page(self) -> QWidget:
        group = QGroupBox("掩码攻击")
        layout = QVBoxLayout(group)
        line = QHBoxLayout()
        line.addWidget(QLabel("掩码:"))
        self.mask_edit = QLineEdit("?l?l?l?l")
        self.mask_edit.setPlaceholderText("例如 ?l?l?d?d, 支持 ?l ?u ?d ?h ?H ?s ?a ??")
        line.addWidget(self.mask_edit, 1)
        layout.addLayout(line)
        help_label = QLabel(
            "?l=小写  ?u=大写  ?d=数字  ?h=小写hex  ?H=大写hex  "
            "?s=符号  ?a=全部可打印  ??=问号")
        help_label.setStyleSheet("color:#888;")
        layout.addWidget(help_label)
        return group

    def _on_mode_changed(self, index: int) -> None:
        self.stack.setCurrentIndex(max(0, min(index, self.stack.count() - 1)))

    def _append_charset(self, chars: str) -> None:
        current = self.charset_edit.text()
        merged = "".join(dict.fromkeys(current + chars))
        self.charset_edit.setText(merged)

    def _choose_wordlist(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择密码字典", "", "文本 (*.txt *.dic *.lst);;所有文件 (*)")
        if path:
            self.wordlist_edit.setText(path)

    def _on_start(self) -> None:
        if not self._path:
            QMessageBox.information(self, "MiscKit", "请先打开 ZIP 文件")
            return
        if self._worker is not None:
            return
        mode = self.mode_combo.currentData() or "dictionary"
        config = zipcrack.CrackConfig(
            path=self._path,
            mode=mode,
            wordlist=self.wordlist_edit.text().strip(),
            charset=self.charset_edit.text(),
            min_length=self.min_length.value(),
            max_length=self.max_length.value(),
            mask=self.mask_edit.text(),
            encoding=self.encoding_combo.currentData() or "utf-8",
        )
        self.recovery_log.clear()
        self._found_password = None
        self._found_password_bytes = b""
        self._result_received = False
        self.result_label.setText("密码:—")
        self.btn_copy_pwd.setEnabled(False)
        self.progress.setRange(0, 0)
        self.progress.setValue(0)
        self.status.setText("正在准备密码恢复…")
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self._worker = CrackWorker(config)
        self._worker.progress.connect(self._on_progress)
        self._worker.resultReady.connect(self._on_result)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.start()

    def _on_stop(self) -> None:
        if self._worker is not None:
            self._worker.stop()
            self.btn_stop.setEnabled(False)
            self.status.setText("正在停止…")

    def _on_progress(self, tried: int, total: int, speed: float,
                     current: str) -> None:
        if total > 0 and total <= 2_000_000_000:
            self.progress.setRange(0, total)
            self.progress.setValue(min(tried, total))
            remaining = (total - tried) / speed if speed > 0 else float("inf")
            eta = zipcrack.format_duration(remaining)
        else:
            self.progress.setRange(0, 0)
            eta = "--"
        self.status.setText(
            f"已尝试 {tried:,} / {total:,}  |  {speed:,.0f} pwd/s  |  剩余 {eta}  |  当前: {current[:40]}")

    def _on_result(self, result: zipcrack.CrackResult) -> None:
        self._result_received = True
        if result.path and result.path != self._path:
            return
        self.progress.setRange(0, 1000)
        if result.password:
            self.progress.setValue(1000)
            self._found_password = result.password
            self._found_password_bytes = result.password_bytes
            self.result_label.setText(f"密码:{result.password}")
            self.btn_copy_pwd.setEnabled(True)
            self.status.setText(
                f"✓ 已找到密码,尝试 {result.tried:,} 次,耗时 {result.elapsed:.2f}s"
                f",{result.speed:,.0f} pwd/s")
            self.recovery_log.appendPlainText(
                f"✓ 密码 = {result.password}\n"
                f"  条目 = {result.entry_name}\n"
                f"  尝试 = {result.tried:,}  耗时 = {result.elapsed:.2f}s  "
                f"速度 = {result.speed:,.0f} pwd/s")
            QApplication.beep()
        elif result.cancelled:
            self.progress.setValue(0)
            self.status.setText(f"已停止,尝试 {result.tried:,} 次")
            self.recovery_log.appendPlainText(f"已停止,尝试 {result.tried:,} 次")
        elif result.error:
            self.progress.setValue(0)
            self.status.setText("恢复失败:" + result.error)
            self.recovery_log.appendPlainText("⚠ " + result.error)
        else:
            self.progress.setValue(1000)
            self.status.setText(f"未找到密码,已尝试 {result.tried:,} 次")
            self.recovery_log.appendPlainText(
                f"未找到密码,已尝试 {result.tried:,} 次,耗时 {result.elapsed:.2f}s")

    def _on_worker_finished(self) -> None:
        # 极端情况下线程没有发出 resultReady(例如未捕获异常),这里兜底恢复按钮。
        if not self._result_received:
            self._on_result(zipcrack.CrackResult(
                path=self._path, error="恢复线程异常退出,未返回结果"))
        self._worker = None
        self.btn_stop.setEnabled(False)
        has_encrypted = bool(
            self._info and any(entry.flags & 1 for entry in self._info.entries))
        self.btn_start.setEnabled(has_encrypted)

    def _on_copy_password(self) -> None:
        if self._found_password:
            QGuiApplication.clipboard().setText(self._found_password)
            self.status.setText("密码已复制到剪贴板")

    # ---------------- 载入 / 结构刷新 ----------------
    def _choose_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择 ZIP", "", "ZIP (*.zip *.docx *.xlsx *.pptx *.jar *.apk *.epub)")
        if path:
            self.load_file(path)

    def load_file(self, path: str) -> bool:
        if self._worker is not None:
            self._worker.stop()
            self._worker.wait(3000)
            self._worker = None
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            QMessageBox.warning(self, "MiscKit", f"读取文件失败:{e}")
            return False
        self._path = path
        self._data = data
        self._found_password = None
        self._found_password_bytes = b""
        self.file_label.setText(f"{path}  ({len(data):,} 字节)")
        self._refresh()
        return True

    def _refresh(self) -> None:
        self._info = zipcrack.inspect(self._data)
        info = self._info
        self.table.setRowCount(0)
        self.log.clear()
        self.btn_extract.setEnabled(bool(info.entries))
        self.btn_repair.setEnabled(any(entry.pseudo for entry in info.entries))
        encrypted = [entry for entry in info.entries if entry.flags & 1]
        self.btn_start.setEnabled(bool(encrypted))
        if hasattr(self, "result_label"):
            self.result_label.setText("密码:—")
            self.btn_copy_pwd.setEnabled(False)
        comment = "".join(ch if ch.isprintable() else "." for ch in info.comment)
        self.comment_label.setText(
            f"压缩包注释:{comment}" if comment else "压缩包注释:(无)")
        if info.error:
            self.log.appendPlainText(f"⚠ {info.error}")
            return
        method_names = {0: "存储", 8: "Deflate", 12: "BZip2", 14: "LZMA"}
        self.table.setRowCount(len(info.entries))
        for row, entry in enumerate(info.entries):
            values = [
                entry.name,
                method_names.get(entry.method, str(entry.method)),
                f"{entry.size:,}",
                f"{entry.compressed_size:,}",
                f"{entry.crc:08X}",
                "是" if entry.flags & 1 else "否",
                "是" if entry.aes else "否",
                "是 ⚠" if entry.pseudo else "否",
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if entry.pseudo:
                    item.setToolTip(entry.reason)
                if col == 0:
                    mark_item(item)
                self.table.setItem(row, col, item)
        pseudo = [entry for entry in info.entries if entry.pseudo]
        if pseudo:
            self.log.appendPlainText(f"⚠ 检测到 {len(pseudo)} 个伪加密条目")
            for entry in pseudo:
                self.log.appendPlainText(f"  - {entry.name}:{entry.reason}")
        else:
            self.log.appendPlainText("✓ 未发现伪加密条目")
        if encrypted:
            self.log.appendPlainText(
                f"检测到 {len(encrypted)} 个加密条目,可在「密码恢复」页签尝试 ZipCrypto 密码恢复。")
        # 额外调用一次结构解析,确保 EOCD/注释等异常也能记录到日志。
        nodes, end = fileparse.parse_zip(self._data)
        if nodes:
            self.log.appendPlainText(
                f"结构解析:{len(nodes)} 个节点,逻辑结束 offset {end:,}")

    def _on_repair(self) -> None:
        if not self._data:
            return
        fixed, count = zipcrack.repair_pseudo_encryption(self._data)
        if not count:
            QMessageBox.information(self, "MiscKit", "没有需要修复的伪加密条目")
            return
        base = os.path.splitext(self._path)[0] or "repaired"
        path, _ = QFileDialog.getSaveFileName(
            self, "保存修复后的 ZIP", base + "_fixed.zip", "ZIP (*.zip)")
        if not path:
            return
        try:
            with open(path, "wb") as f:
                f.write(fixed)
        except OSError as e:
            QMessageBox.warning(self, "MiscKit", f"保存失败:{e}")
            return
        self.log.appendPlainText(f"✓ 已清除 {count} 个条目的伪加密标志:{path}")
        QMessageBox.information(self, "MiscKit", f"伪加密修复完成:\n{path}")
        self.load_file(path)

    def _on_extract(self) -> None:
        if not self._data:
            return
        target = QFileDialog.getExistingDirectory(self, "选择解压目录")
        if not target:
            return
        password = self._found_password_bytes or None
        try:
            with zipfile.ZipFile(io.BytesIO(self._data)) as zf:
                root = os.path.realpath(target)
                for info in zf.infolist():
                    destination = os.path.realpath(os.path.join(root, info.filename))
                    try:
                        inside = os.path.commonpath([root, destination]) == root
                    except ValueError:
                        inside = False
                    if not inside:
                        self.log.appendPlainText(f"⚠ 跳过越界路径:{info.filename}")
                        continue
                    zf.extract(info, target, pwd=password)
        except (OSError, zipfile.BadZipFile, RuntimeError) as e:
            QMessageBox.warning(self, "MiscKit", f"解压失败:{e}")
            return
        self.log.appendPlainText(f"✓ 已解压到:{target}")
        QMessageBox.information(self, "MiscKit", f"解压完成:\n{target}")

    def shutdown(self) -> None:
        if self._worker is not None:
            self._worker.stop()
            self._worker.wait(3000)
            self._worker = None
