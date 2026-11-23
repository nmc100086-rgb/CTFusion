"""ZIP 分析页签:结构 / 伪加密 / 密码恢复 / 安全解压。"""

from __future__ import annotations

import os
import threading
import zipfile

from PySide6.QtCore import QThread, Signal
from PySide6.QtGui import QAction, QGuiApplication
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
    QMenu,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from core import fileparse, zipcrack
from ui import save_utils
from ui.highlight import install_flag_highlighter, mark_item
from ui.zip_attack_panels import CrcAttackPanel, KpaAttackPanel


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


class ExtractWorker(QThread):
    """Extract archive entries without blocking the UI."""

    progress = Signal(int, int, str)
    resultReady = Signal(bool, str)

    def __init__(self, path: str, target: str, password: bytes | None,
                 allow_risky: bool = False) -> None:
        super().__init__()
        self.path = path
        self.target = target
        self.password = password
        self.single_limit = (
            zipcrack.HARD_EXTRACT_SINGLE
            if allow_risky else zipcrack.MAX_EXTRACT_SINGLE
        )
        self.total_limit = (
            zipcrack.HARD_EXTRACT_TOTAL
            if allow_risky else zipcrack.MAX_EXTRACT_TOTAL
        )
        self.cancel_event = threading.Event()

    def run(self) -> None:
        extracted = 0
        total_written = 0
        try:
            with zipfile.ZipFile(self.path) as archive:
                entries = archive.infolist()
                for index, info in enumerate(entries, 1):
                    if self.cancel_event.is_set():
                        self.resultReady.emit(
                            False, f"已停止,已解压 {extracted}/{len(entries)} 个条目")
                        return
                    if not zipcrack.safe_extract_path(self.target, info.filename):
                        self.resultReady.emit(
                            False, f"检测到越界路径,已中止:{info.filename}")
                        return
                    destination = zipcrack.safe_extract_path(
                        self.target, info.filename)
                    assert destination is not None
                    if info.is_dir():
                        os.makedirs(destination, exist_ok=True)
                        extracted += 1
                        self.progress.emit(index, len(entries), info.filename)
                        continue
                    os.makedirs(os.path.dirname(destination), exist_ok=True)
                    written = 0
                    try:
                        with archive.open(info, pwd=self.password) as source, \
                                open(destination, "wb") as target_file:
                            while True:
                                if self.cancel_event.is_set():
                                    raise RuntimeError("用户取消")
                                chunk = source.read(1024 * 1024)
                                if not chunk:
                                    break
                                written += len(chunk)
                                total_written += len(chunk)
                                if (written > self.single_limit
                                        or total_written > self.total_limit):
                                    raise RuntimeError("解压数据超过安全上限")
                                target_file.write(chunk)
                    except Exception:
                        try:
                            os.remove(destination)
                        except OSError:
                            pass
                        raise
                    extracted += 1
                    self.progress.emit(index, len(entries), info.filename)
        except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
            self.resultReady.emit(False, f"解压失败:{exc}")
            return
        self.resultReady.emit(True, f"已解压 {extracted} 个条目到:\n{self.target}")

    def stop(self) -> None:
        self.cancel_event.set()


class ZipPanel(QWidget):
    """ZIP 结构查看、伪加密修复、密码恢复与安全解压。"""

    openRequested = Signal(str)
    pathChanged = Signal(str, str)

    def __init__(self) -> None:
        super().__init__()
        self._path = ""
        self._data = b""
        self._info: zipcrack.ZipInspect | None = None
        self._worker: CrackWorker | None = None
        self._extract_worker: ExtractWorker | None = None
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
        self.crc_panel = CrcAttackPanel()
        self.kpa_panel = KpaAttackPanel()
        self.crc_panel.plaintextSelected.connect(self._on_crc_plaintext)
        self.tabs.addTab(self.crc_panel, "CRC 爆破")
        self.tabs.addTab(self.kpa_panel, "已知明文 (KPA)")
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
        self.status = QLabel("载入 ZIP 后选择模式开始恢复；仅支持 ZipCrypto，不支持 AES。")
        layout.addWidget(self.status)
        self.recovery_hint = QLabel(
            "恢复不出来时依次检查：①「结构」页看是否 AES 加密（本工具不支持）；"
            "②密码是否确实在字典/掩码范围内；③中文密码把编码改为 GBK 或自动；"
            "④掩码写 ???? 并在下拉菜单勾选字符集，?d/?l 固定写法已移除；"
            "⑤0 字节加密条目无法可靠校验密码。")
        self.recovery_hint.setWordWrap(True)
        self.recovery_hint.setStyleSheet("color:#888; font-size:12px;")
        layout.addWidget(self.recovery_hint)

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
        self.mask_edit = QLineEdit("????")
        self.mask_edit.setPlaceholderText("例如 qctf2026????")
        line.addWidget(self.mask_edit, 1)
        layout.addLayout(line)

        wildcard_line = QHBoxLayout()
        wildcard_line.addWidget(QLabel("裸 ? 代表:"))
        self.wildcard_button = QToolButton()
        self.wildcard_button.setPopupMode(QToolButton.InstantPopup)
        self.wildcard_menu = QMenu(self.wildcard_button)
        self.wildcard_actions: dict[str, QAction] = {}
        for code, label, _chars in zipcrack.WILDCARD_OPTIONS:
            action = QAction(label, self.wildcard_menu)
            action.setCheckable(True)
            action.setData(code)
            action.triggered.connect(
                lambda checked, current=action: self._on_wildcard_action(
                    current, checked))
            self.wildcard_menu.addAction(action)
            self.wildcard_actions[code] = action
            if code in ("l", "u", "d"):
                action.setChecked(True)
        self.wildcard_button.setMenu(self.wildcard_menu)
        wildcard_line.addWidget(self.wildcard_button)
        wildcard_line.addStretch()
        layout.addLayout(wildcard_line)
        self._update_wildcard_label()

        help_label = QLabel(
            "每个裸 ? 都使用上方下拉菜单多选的字符集;"
            "?l/?u/?d 等固定写法已移除。"
            "例如 4 位数字:掩码写 ????，下拉勾选“数字”。"
            "字面问号请写 \\?。")
        help_label.setStyleSheet("color:#888;")
        help_label.setWordWrap(True)
        layout.addWidget(help_label)
        return group

    def _on_wildcard_action(self, action: QAction, checked: bool) -> None:
        code = str(action.data())
        if action.isChecked() != checked:
            action.blockSignals(True)
            action.setChecked(checked)
            action.blockSignals(False)
        if checked and code == "a":
            for other_code, other in self.wildcard_actions.items():
                if other_code != "a":
                    other.blockSignals(True)
                    other.setChecked(False)
                    other.blockSignals(False)
        elif checked:
            all_action = self.wildcard_actions["a"]
            all_action.blockSignals(True)
            all_action.setChecked(False)
            all_action.blockSignals(False)

        if not any(item.isChecked() for item in self.wildcard_actions.values()):
            action.blockSignals(True)
            action.setChecked(True)
            action.blockSignals(False)
        self._update_wildcard_label()

    def _selected_wildcard_codes(self) -> list[str]:
        return [
            code for code, action in self.wildcard_actions.items()
            if action.isChecked()
        ]

    def _update_wildcard_label(self) -> None:
        codes = self._selected_wildcard_codes()
        labels = {
            code: label for code, label, _chars in zipcrack.WILDCARD_OPTIONS
        }
        chars = zipcrack.wildcard_charset(codes)
        shown = [labels[code] for code in codes if code in labels]
        self.wildcard_button.setText(
            f"{' + '.join(shown)} ({len(chars)} 字符)")
        self.wildcard_button.setToolTip(
            "选择“所有可打印字符”时会自动取消其他选项")

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
            QMessageBox.information(self, "CTFusion", "请先打开 ZIP 文件")
            return
        if self._worker is not None or self._extract_worker is not None:
            return
        mode = self.mode_combo.currentData() or "dictionary"
        wildcard_chars = zipcrack.wildcard_charset(
            self._selected_wildcard_codes())
        if mode == "mask":
            mask = self.mask_edit.text().strip()
            if not mask:
                QMessageBox.warning(
                    self, "CTFusion",
                    "掩码不能为空。\n\n"
                    "例如 4 位数字密码:掩码写 ????，"
                    "再在上方下拉菜单勾选“数字”。")
                return
            try:
                zipcrack.parse_mask(mask, wildcard_chars)
            except ValueError as e:
                QMessageBox.warning(
                    self, "CTFusion",
                    f"{e}\n\n"
                    "示例:4 位数字密码 → 掩码 ????，下拉勾选“数字”;"
                    "4 位小写字母 → ????，下拉勾选“小写字母”。")
                return
        if mode == "dictionary" and not self.wordlist_edit.text().strip():
            QMessageBox.warning(self, "CTFusion", "请先选择密码字典文件")
            return
        if mode == "brute" and not self.charset_edit.text():
            QMessageBox.warning(self, "CTFusion", "暴力破解字符集不能为空")
            return
        config = zipcrack.CrackConfig(
            path=self._path,
            mode=mode,
            wordlist=self.wordlist_edit.text().strip(),
            charset=self.charset_edit.text(),
            min_length=self.min_length.value(),
            max_length=self.max_length.value(),
            mask=self.mask_edit.text(),
            wildcard_chars=wildcard_chars,
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
            f"已尝试 {tried:,} / {total:,}  |  {speed:,.0f} 个/秒  |  剩余 {eta}  |  当前：{current[:40]}")

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
                f"，{result.speed:,.0f} 个/秒")
            self.recovery_log.appendPlainText(
                f"✓ 密码 = {result.password}\n"
                f"  条目 = {result.entry_name}\n"
                f"  尝试 = {result.tried:,}  耗时 = {result.elapsed:.2f}s  "
                f"速度 = {result.speed:,.0f} 个/秒")
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
        self.btn_start.setEnabled(bool(self._crackable_entries()))

    def _on_copy_password(self) -> None:
        if self._found_password:
            QGuiApplication.clipboard().setText(self._found_password)
            self.status.setText("密码已复制到剪贴板")

    def _on_crc_plaintext(self, data: bytes, offset: int) -> None:
        self.kpa_panel.receive_plaintext(data, offset)
        self.tabs.setCurrentWidget(self.kpa_panel)

    # ---------------- 载入 / 结构刷新 ----------------
    def _choose_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择 ZIP", "", "ZIP (*.zip *.docx *.xlsx *.pptx *.jar *.apk *.epub)")
        if path:
            self.openRequested.emit(path)

    def load_file(self, path: str) -> bool:
        if not self._stop_background():
            QMessageBox.warning(
                self, "CTFusion",
                "后台任务仍在停止中,请稍后再打开其他 ZIP。")
            return False
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            QMessageBox.warning(self, "CTFusion", f"读取文件失败:{e}")
            return False
        self._path = path
        self._data = data
        self._found_password = None
        self._found_password_bytes = b""
        self.file_label.setText(f"{path}  ({len(data):,} 字节)")
        self._refresh()
        return True

    def _crackable_entries(self) -> list[zipcrack.ZipEntry]:
        if self._info is None:
            return []
        return [
            entry for entry in self._info.entries
            if (entry.flags & 1) and not entry.aes
            and not (entry.flags & 0x40)
            and entry.size > 0 and entry.compressed_size > 12
        ]

    def _refresh(self) -> None:
        self._info = zipcrack.inspect(self._data)
        info = self._info
        self.table.setRowCount(0)
        self.log.clear()
        self.btn_extract.setEnabled(bool(info.entries))
        self.btn_repair.setEnabled(any(entry.pseudo for entry in info.entries))
        encrypted = [entry for entry in info.entries if entry.flags & 1]
        aes_entries = [entry for entry in encrypted if entry.aes]
        zipcrypto_entries = [
            entry for entry in encrypted
            if not entry.aes and not (entry.flags & 0x40)
        ]
        crackable = [
            entry for entry in zipcrypto_entries
            if entry.size > 0 and entry.compressed_size > 12
        ]
        self.btn_start.setEnabled(bool(crackable))
        if hasattr(self, "result_label"):
            self.result_label.setText("密码:—")
            self.btn_copy_pwd.setEnabled(False)
        comment = "".join(ch if ch.isprintable() else "." for ch in info.comment)
        self.comment_label.setText(
            f"压缩包注释:{comment}" if comment else "压缩包注释:(无)")
        self.crc_panel.set_archive(self._path, self._data, info)
        self.kpa_panel.set_archive(self._path, self._data, info)
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
        if crackable:
            self.log.appendPlainText(
                f"检测到 {len(crackable)} 个可校验的 ZipCrypto 条目,"
                "可在「密码恢复」页签尝试字典/暴力/掩码恢复。")
            self.status.setText(
                "可尝试 ZipCrypto 密码恢复；只支持 ZipCrypto，不支持 AES。")
        elif aes_entries:
            self.log.appendPlainText(
                f"⚠ 检测到 {len(aes_entries)} 个 AES 加密条目。"
                "本工具只支持 ZipCrypto；请用支持 AES 的解压工具输入密码解压。")
            self.status.setText(
                "检测到 AES 加密，本工具只支持 ZipCrypto，无法恢复。")
        elif zipcrypto_entries:
            self.log.appendPlainText(
                "⚠ 加密条目为空(0 字节)或压缩数据不足,"
                "ZipCrypto 无法可靠校验密码,已禁用密码恢复。")
            self.status.setText(
                "加密条目为空,ZipCrypto 密码无法可靠验证。")
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
            QMessageBox.information(self, "CTFusion", "没有需要修复的伪加密条目")
            return
        base = os.path.splitext(self._path)[0] or "repaired"
        path, _ = QFileDialog.getSaveFileName(
            self, "保存修复后的 ZIP", base + "_fixed.zip", "ZIP (*.zip)")
        if not path:
            return
        if not save_utils.write_bytes(self, fixed, path, "archive"):
            return
        old_path = self._path
        self.log.appendPlainText(f"✓ 已清除 {count} 个条目的伪加密标志:{path}")
        QMessageBox.information(self, "CTFusion", f"伪加密修复完成:\n{path}")
        if self.load_file(path):
            self.pathChanged.emit(old_path, path)

    def _on_extract(self) -> None:
        if not self._data:
            return
        target = QFileDialog.getExistingDirectory(self, "选择解压目录")
        if not target:
            return
        password = self._found_password_bytes or None
        try:
            with zipfile.ZipFile(self._path) as archive:
                entries = archive.infolist()
        except (OSError, zipfile.BadZipFile, RuntimeError) as e:
            QMessageBox.warning(self, "CTFusion", f"解压失败:{e}")
            return
        risks = zipcrack.extraction_risks(entries)
        allow_risky = False
        if risks:
            detail = "\n".join(f"• {item}" for item in risks)
            choice = QMessageBox.warning(
                self, "检测到高风险 ZIP",
                "以下内容超过默认安全限制:\n\n"
                f"{detail}\n\n仍要继续解压吗?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if choice != QMessageBox.Yes:
                self.log.appendPlainText("⚠ 已取消高风险 ZIP 解压")
                return
            allow_risky = True
        if self._extract_worker is not None:
            return
        self.progress.setRange(0, max(1, len(entries)))
        self.progress.setValue(0)
        self.status.setText("正在后台解压…")
        self.btn_extract.setEnabled(False)
        self.btn_open.setEnabled(False)
        self.btn_repair.setEnabled(False)
        worker = ExtractWorker(self._path, target, password, allow_risky)
        worker.progress.connect(self._on_extract_progress)
        worker.resultReady.connect(self._on_extract_result)
        worker.finished.connect(self._on_extract_finished)
        self._extract_worker = worker
        worker.start()

    def _on_extract_progress(self, done: int, total: int, name: str) -> None:
        self.progress.setRange(0, max(1, total))
        self.progress.setValue(done)
        self.status.setText(f"正在解压 {done}/{total}:{name[:80]}")

    def _on_extract_result(self, ok: bool, message: str) -> None:
        self.log.appendPlainText(("✓ " if ok else "⚠ ") + message)
        if ok:
            self.progress.setValue(self.progress.maximum())
            QMessageBox.information(self, "CTFusion", message)
        else:
            self.progress.setValue(0)
            QMessageBox.warning(self, "CTFusion", message)

    def _on_extract_finished(self) -> None:
        self._extract_worker = None
        self.btn_open.setEnabled(True)
        self.btn_extract.setEnabled(bool(self._info and self._info.entries))
        self.btn_repair.setEnabled(bool(
            self._info and any(entry.pseudo for entry in self._info.entries)))
        if self.status.text().startswith("正在"):
            self.status.setText("解压任务已结束")

    def _stop_background(self, timeout_ms: int = 5_000) -> bool:
        workers = [worker for worker in (self._worker, self._extract_worker)
                   if worker is not None]
        for worker in workers:
            worker.stop()
        for worker in workers:
            if worker.isRunning() and not worker.wait(timeout_ms):
                return False
        if self._worker is not None and self._worker.isFinished():
            self._worker = None
            self.btn_stop.setEnabled(False)
            self.btn_start.setEnabled(bool(self._crackable_entries()))
        if self._extract_worker is not None and self._extract_worker.isFinished():
            self._on_extract_finished()
        if not self.crc_panel.shutdown() or not self.kpa_panel.shutdown():
            return False
        return True

    def shutdown(self) -> bool:
        return self._stop_background()

    def clear(self) -> bool:
        if not self._stop_background():
            return False
        self._path = ""
        self._data = b""
        self._info = None
        self._found_password = None
        self._found_password_bytes = b""
        self.table.setRowCount(0)
        self.comment_label.setText("压缩包注释:(无)")
        self.file_label.setText("拖入 ZIP 文件开始分析")
        self.log.clear()
        self.recovery_log.clear()
        self.result_label.setText("密码:—")
        self.btn_copy_pwd.setEnabled(False)
        self.btn_extract.setEnabled(False)
        self.btn_repair.setEnabled(False)
        self.btn_start.setEnabled(False)
        self.progress.setRange(0, 1000)
        self.progress.setValue(0)
        self.crc_panel.clear()
        self.kpa_panel.clear()
        self.status.setText("载入 ZIP 后选择模式开始恢复；仅支持 ZipCrypto，不支持 AES。")
        return True
