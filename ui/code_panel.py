"""代码格式化页签。"""

from __future__ import annotations

import os

from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from core import codefmt


class CodePanel(QWidget):
    """把不规则的 CTF 代码整理成可读格式。"""

    def __init__(self) -> None:
        super().__init__()
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("语言:"))
        self.lang_combo = QComboBox()
        for language in codefmt.LANGUAGES:
            self.lang_combo.addItem(language, language)
        self.lang_combo.currentIndexChanged.connect(self._on_language_changed)
        bar.addWidget(self.lang_combo)
        self.btn_open = QPushButton("打开代码…")
        self.btn_open.clicked.connect(self._on_open)
        bar.addWidget(self.btn_open)
        self.btn_format = QPushButton("格式化")
        self.btn_format.clicked.connect(self._on_format)
        bar.addWidget(self.btn_format)
        self.btn_copy = QPushButton("复制结果")
        self.btn_copy.clicked.connect(self._on_copy)
        bar.addWidget(self.btn_copy)
        bar.addStretch()
        self.status = QLabel("JSON / Python / JS / HTML / CSS / C / C++ / Java / PHP")
        self.status.setStyleSheet("color:#888;")
        bar.addWidget(self.status)
        layout.addLayout(bar)

        splitter = QSplitter()
        self.input_edit = QPlainTextEdit()
        self.input_edit.setPlaceholderText("粘贴或拖入不规则代码")
        self.input_edit.setFont(QFont("Consolas"))
        self.output_edit = QPlainTextEdit()
        self.output_edit.setReadOnly(True)
        self.output_edit.setFont(QFont("Consolas"))
        splitter.addWidget(self.input_edit)
        splitter.addWidget(self.output_edit)
        splitter.setSizes([500, 500])
        layout.addWidget(splitter, 1)

    def _on_language_changed(self, _index: int = -1) -> None:
        self.status.setText("选择语言后点击格式化")

    def _on_open(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "打开代码文件", "",
            "代码 (*.py *.js *.json *.html *.htm *.css *.c *.h *.cpp *.hpp *.java *.php);;所有文件 (*)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError as e:
            QMessageBox.warning(self, "CTFusion", f"读取失败:{e}")
            return
        self.input_edit.setPlainText(text)
        ext = os.path.splitext(path)[1].lower()
        mapping = {
            ".py": "Python", ".js": "JavaScript", ".json": "JSON",
            ".html": "HTML", ".htm": "HTML", ".css": "CSS",
            ".c": "C", ".h": "C", ".cpp": "C++", ".hpp": "C++",
            ".java": "Java", ".php": "PHP",
        }
        language = mapping.get(ext)
        if language:
            index = self.lang_combo.findData(language)
            if index >= 0:
                self.lang_combo.setCurrentIndex(index)

    def _on_format(self) -> None:
        language = self.lang_combo.currentData() or "JSON"
        try:
            result = codefmt.format_code(self.input_edit.toPlainText(), language)
        except codefmt.FormatError as e:
            QMessageBox.warning(self, "CTFusion", str(e))
            return
        self.output_edit.setPlainText(result)
        self.status.setText(f"已格式化:{language}")

    def _on_copy(self) -> None:
        QGuiApplication.clipboard().setText(self.output_edit.toPlainText())
        self.status.setText("结果已复制")
