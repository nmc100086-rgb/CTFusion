"""JWT 解析与生成/伪造页签。"""

from __future__ import annotations

import json

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core import jwt_tool


def _text_edit(placeholder: str, read_only: bool = False) -> QPlainTextEdit:
    edit = QPlainTextEdit()
    edit.setPlaceholderText(placeholder)
    edit.setReadOnly(read_only)
    edit.setFont(QFont("Consolas"))
    return edit


class JwtPanel(QWidget):
    """JWT 解析、签名校验、HS/RS 生成与 none 伪造。"""

    def __init__(self) -> None:
        super().__init__()
        self._decoded: jwt_tool.DecodedJwt | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("JWT Token:"))
        self.token_edit = _text_edit("粘贴 header.payload.signature")
        self.token_edit.setMaximumHeight(90)
        layout.addWidget(self.token_edit)

        bar = QHBoxLayout()
        self.btn_decode = QPushButton("解析")
        self.btn_decode.clicked.connect(self._on_decode)
        bar.addWidget(self.btn_decode)
        self.btn_copy = QPushButton("复制 Token")
        self.btn_copy.clicked.connect(self._on_copy_token)
        bar.addWidget(self.btn_copy)
        self.btn_clear = QPushButton("清空")
        self.btn_clear.clicked.connect(self._on_clear)
        bar.addWidget(self.btn_clear)
        self.status = QLabel("HS256/384/512、none、RS256")
        self.status.setStyleSheet("color:#888;")
        bar.addWidget(self.status, 1)
        layout.addLayout(bar)

        splitter = QSplitter(Qt.Horizontal)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        self.decoded_tabs = QTabWidget()
        self.header_view = _text_edit("Header", True)
        self.payload_view = _text_edit("Payload", True)
        self.signature_view = _text_edit("Signature", True)
        self.decoded_tabs.addTab(self.header_view, "Header")
        self.decoded_tabs.addTab(self.payload_view, "Payload")
        self.decoded_tabs.addTab(self.signature_view, "Signature")
        left_layout.addWidget(self.decoded_tabs)
        splitter.addWidget(left)

        right = QGroupBox("生成 / 伪造")
        right_layout = QVBoxLayout(right)
        alg_row = QHBoxLayout()
        alg_row.addWidget(QLabel("算法:"))
        self.alg_combo = QComboBox()
        for alg in ("HS256", "HS384", "HS512", "none", "RS256"):
            self.alg_combo.addItem(alg, alg)
        alg_row.addWidget(self.alg_combo)
        alg_row.addWidget(QLabel("密钥/私钥:"))
        self.secret_edit = _text_edit("HMAC secret，或 RS256 PEM 私钥")
        self.secret_edit.setMaximumHeight(70)
        right_layout.addLayout(alg_row)
        right_layout.addWidget(self.secret_edit)

        right_layout.addWidget(QLabel("Header JSON:"))
        self.header_edit = _text_edit('{"typ":"JWT","alg":"HS256"}')
        self.header_edit.setMaximumHeight(100)
        right_layout.addWidget(self.header_edit)
        right_layout.addWidget(QLabel("Payload JSON:"))
        self.payload_edit = _text_edit('{"sub":"admin","role":"admin"}')
        self.payload_edit.setMinimumHeight(120)
        right_layout.addWidget(self.payload_edit)

        gen_bar = QHBoxLayout()
        self.btn_generate = QPushButton("生成 Token")
        self.btn_generate.clicked.connect(self._on_generate)
        gen_bar.addWidget(self.btn_generate)
        self.btn_copy_generated = QPushButton("复制生成结果")
        self.btn_copy_generated.clicked.connect(self._on_copy_generated)
        gen_bar.addWidget(self.btn_copy_generated)
        gen_bar.addStretch()
        right_layout.addLayout(gen_bar)
        self.generated_edit = _text_edit("生成结果", True)
        self.generated_edit.setMaximumHeight(80)
        right_layout.addWidget(self.generated_edit)
        splitter.addWidget(right)
        splitter.setSizes([520, 480])
        layout.addWidget(splitter, 1)
        self._set_template()

    def _set_template(self) -> None:
        self.header_edit.setPlainText(
            json.dumps({"typ": "JWT", "alg": "HS256"}, ensure_ascii=False, indent=2))
        self.payload_edit.setPlainText(
            json.dumps({"sub": "admin", "role": "admin"}, ensure_ascii=False, indent=2))

    def _on_clear(self) -> None:
        self.token_edit.clear()
        self.header_view.clear()
        self.payload_view.clear()
        self.signature_view.clear()
        self.generated_edit.clear()
        self.status.setText("已清空")

    def _on_decode(self) -> None:
        try:
            decoded = jwt_tool.decode(self.token_edit.toPlainText())
        except jwt_tool.JwtError as e:
            QMessageBox.warning(self, "CTFusion", str(e))
            return
        self._decoded = decoded
        self.header_view.setPlainText(decoded.header_text)
        self.payload_view.setPlainText(decoded.payload_text)
        self.signature_view.setPlainText(decoded.signature_text)
        self.header_edit.setPlainText(decoded.header_text)
        self.payload_edit.setPlainText(decoded.payload_text)
        alg = decoded.header.get("alg", "HS256")
        index = self.alg_combo.findData(alg)
        if index >= 0:
            self.alg_combo.setCurrentIndex(index)
        self.status.setText("解析成功，可修改 Payload 后重新生成/伪造")

    def _on_generate(self) -> None:
        try:
            header = json.loads(self.header_edit.toPlainText())
            payload = json.loads(self.payload_edit.toPlainText())
        except json.JSONDecodeError as e:
            QMessageBox.warning(self, "CTFusion", f"JSON 格式错误:{e}")
            return
        alg = self.alg_combo.currentData() or "HS256"
        try:
            token = jwt_tool.encode(
                payload, self.secret_edit.toPlainText(), alg, header)
        except jwt_tool.JwtError as e:
            QMessageBox.warning(self, "CTFusion", str(e))
            return
        self.generated_edit.setPlainText(token)
        self.token_edit.setPlainText(token)
        self.status.setText(f"已生成 {alg} Token，签名长度 {len(token.split('.')[-1])}")

    def _on_copy_token(self) -> None:
        QGuiApplication.clipboard().setText(self.token_edit.toPlainText())
        self.status.setText("Token 已复制")

    def _on_copy_generated(self) -> None:
        QGuiApplication.clipboard().setText(self.generated_edit.toPlainText())
        self.status.setText("生成结果已复制")
