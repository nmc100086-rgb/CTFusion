"""ZIP 分析页签:条目列表、注释、伪加密检测/修复与安全解压。"""

from __future__ import annotations

import io
import os
import zipfile

from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import fileparse, zipcrack
from ui.highlight import install_flag_highlighter, mark_item


class ZipPanel(QWidget):
    """ZIP 伪加密修复 / 结构查看 / 安全解压。"""

    def __init__(self) -> None:
        super().__init__()
        self._path = ""
        self._data = b""
        self._info: zipcrack.ZipInspect | None = None
        self._build_ui()

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

        self.comment_label = QLabel("压缩包注释:(无)")
        self.comment_label.setWordWrap(True)
        layout.addWidget(self.comment_label)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["文件名", "方法", "原始大小", "压缩后", "CRC32", "加密", "伪加密"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        for col in range(1, 7):
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

    def _choose_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择 ZIP", "", "ZIP (*.zip *.docx *.xlsx *.pptx *.jar *.apk *.epub)")
        if path:
            self.load_file(path)

    def load_file(self, path: str) -> bool:
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            QMessageBox.warning(self, "MiscKit", f"读取文件失败:{e}")
            return False
        self._path = path
        self._data = data
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
                    zf.extract(info, target)
        except (OSError, zipfile.BadZipFile, RuntimeError) as e:
            QMessageBox.warning(self, "MiscKit", f"解压失败:{e}")
            return
        self.log.appendPlainText(f"✓ 已解压到:{target}")
        QMessageBox.information(self, "MiscKit", f"解压完成:\n{target}")
