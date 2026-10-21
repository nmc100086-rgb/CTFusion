"""编码解码页签:算法下拉、动态参数区、输入/输出区、一键智能解码。"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.chain import smart_decode
from core.codecs import get_all
from core.codecs.base import CodecBase, CodecError


class DecoderPanel(QWidget):
    """编码/解码工作台:手动选算法 + 一键智能识别。"""

    def __init__(self) -> None:
        super().__init__()
        self._param_edits: dict[str, QWidget] = {}
        self._param_labels: list[QLabel] = []
        self._raw_output: str = ""
        self._last_codec: CodecBase | None = None
        self._build_ui()
        self._on_codec_changed(0)

    # ---------------- UI 构建 ----------------
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        # 顶部:算法选择 + 操作按钮
        top = QHBoxLayout()
        top.addWidget(QLabel("算法:"))
        self.combo = QComboBox()
        self.combo.setMinimumWidth(240)
        for codec in get_all():
            self.combo.addItem(f"{codec.category} | {codec.name}", codec)
        self.combo.currentIndexChanged.connect(self._on_codec_changed)
        top.addWidget(self.combo)

        self.btn_encode = QPushButton("编码 ▶")
        self.btn_decode = QPushButton("◀ 解码")
        self.btn_smart = QPushButton("一键智能解码")
        self.btn_encode.clicked.connect(self._on_encode)
        self.btn_decode.clicked.connect(self._on_decode)
        self.btn_smart.clicked.connect(self._on_smart)
        for b in (self.btn_encode, self.btn_decode, self.btn_smart):
            top.addWidget(b)
        top.addStretch()
        layout.addLayout(top)

        # 参数设置区
        self.param_box = QGroupBox("参数设置")
        form = QFormLayout(self.param_box)
        self.key_edit = QLineEdit()
        self.iv_edit = QLineEdit()
        self.alphabet_edit = QLineEdit()
        self.key_label = QLabel("密钥:")
        self.iv_label = QLabel("IV:")
        self.alphabet_label = QLabel("自定义字母表:")
        form.addRow(self.key_label, self.key_edit)
        form.addRow(self.iv_label, self.iv_edit)
        form.addRow(self.alphabet_label, self.alphabet_edit)
        # 动态参数行(按算法 params 声明重建)
        self._dyn_rows: list[tuple[QLabel, QWidget]] = []
        self._dyn_form = form
        layout.addWidget(self.param_box)

        # 输入区
        layout.addWidget(QLabel("输入:"))
        self.input_edit = QPlainTextEdit()
        self.input_edit.setPlaceholderText("在此粘贴明文或密文,支持乱码输入……")
        self.input_edit.setMaximumHeight(130)
        layout.addWidget(self.input_edit)

        # 输出区 + 复制
        out_head = QHBoxLayout()
        out_head.addWidget(QLabel("输出:"))
        out_head.addStretch()
        self.btn_copy = QPushButton("复制输出")
        self.btn_copy.clicked.connect(self._on_copy)
        self.btn_copy_hex = QPushButton("复制 Hex")
        self.btn_copy_hex.setToolTip("以十六进制复制原始输出字节,适合二进制结果")
        self.btn_copy_hex.clicked.connect(self._on_copy_hex)
        out_head.addWidget(self.btn_copy)
        out_head.addWidget(self.btn_copy_hex)
        layout.addLayout(out_head)
        self.output_edit = QPlainTextEdit()
        self.output_edit.setReadOnly(True)
        self.output_edit.setMaximumHeight(130)
        layout.addWidget(self.output_edit)

        # 智能解码结果
        layout.addWidget(QLabel("智能解码结果(双击填入输出区):"))
        self.result_tree = QTreeWidget()
        self.result_tree.setHeaderLabels(["解码路径", "结果预览", "评分"])
        self.result_tree.setColumnWidth(0, 220)
        self.result_tree.setColumnWidth(1, 560)
        self.result_tree.itemDoubleClicked.connect(self._on_hit_double_clicked)
        layout.addWidget(self.result_tree)

    # ---------------- 参数区动态刷新 ----------------
    def _current_codec(self) -> CodecBase:
        return self.combo.currentData()

    def _on_codec_changed(self, _index: int) -> None:
        codec = self._current_codec()
        # 切换算法时清空旧算法的密钥/IV/字母表,避免把旧值带给新算法
        if self._last_codec is not None and codec is not self._last_codec:
            self.key_edit.clear()
            self.iv_edit.clear()
            self.alphabet_edit.clear()
        self._last_codec = codec
        # 固定行按能力声明显隐
        for label, edit, show, hint in (
            (self.key_label, self.key_edit, codec.need_key, codec.key_hint),
            (self.iv_label, self.iv_edit, codec.need_iv, ""),
            (self.alphabet_label, self.alphabet_edit, codec.need_alphabet, codec.alphabet_hint),
        ):
            label.setVisible(show)
            edit.setVisible(show)
            edit.setPlaceholderText(hint)
        # 单向算法禁用解码按钮
        self.btn_decode.setEnabled(not codec.one_way)
        self.btn_decode.setToolTip("该算法为单向哈希,无法解码" if codec.one_way else "")
        # 重建动态参数行
        self._rebuild_dynamic_params(codec)
        # 描述提示
        self.param_box.setToolTip(codec.description)

    def _rebuild_dynamic_params(self, codec: CodecBase) -> None:
        for label, edit in self._dyn_rows:
            self._dyn_form.removeRow(label)
        self._dyn_rows.clear()
        self._param_edits.clear()
        choices_map = getattr(codec, "param_choices", {})
        for name, label_text, default in codec.params:
            label = QLabel(label_text + ":")
            choices = choices_map.get(name)
            if choices:
                edit: QWidget = QComboBox()
                for text, value in choices:
                    edit.addItem(text, value)
                index = edit.findData(default)
                if index >= 0:
                    edit.setCurrentIndex(index)
            else:
                edit = QLineEdit(default)
            self._dyn_form.addRow(label, edit)
            self._dyn_rows.append((label, edit))
            self._param_edits[name] = edit

    def _collect_params(self) -> dict[str, str]:
        params: dict[str, str] = {}
        for name, widget in self._param_edits.items():
            if isinstance(widget, QComboBox):
                data = widget.currentData()
                params[name] = "" if data is None else str(data)
            elif isinstance(widget, QLineEdit):
                params[name] = widget.text()
        return params

    # ---------------- 编解码操作 ----------------
    def _get_input(self) -> str | None:
        text = self.input_edit.toPlainText()
        if not text:
            self._info("请先在输入区填入内容。")
            return None
        return text

    def _run(self, direction: str) -> None:
        text = self._get_input()
        if text is None:
            return
        codec = self._current_codec()
        fn = codec.encode if direction == "encode" else codec.decode
        kwargs: dict[str, str] = {}
        if codec.need_key:
            kwargs["key"] = self.key_edit.text()
        if codec.need_iv:
            kwargs["iv"] = self.iv_edit.text()
        if codec.need_alphabet:
            kwargs["alphabet"] = self.alphabet_edit.text()
        try:
            out = fn(text, **kwargs, **self._collect_params())
        except CodecError as e:
            self._info(str(e))
            return
        except Exception as e:  # 兜底:任何意外都不允许崩溃
            self._info(f"操作失败:{e}\n输入可能不是合法的 {codec.name} 内容。")
            return
        self._raw_output = out
        self.output_edit.setPlainText(self._display(out))

    def _on_encode(self) -> None:
        self._run("encode")

    def _on_decode(self) -> None:
        self._run("decode")

    def _on_copy(self) -> None:
        text = self.output_edit.toPlainText()
        if not text:
            self._info("输出区为空,没有可复制的内容。")
            return
        QGuiApplication.clipboard().setText(text)
        self.btn_copy.setText("已复制 ✓")
        from PySide6.QtCore import QTimer
        QTimer.singleShot(1200, lambda: self.btn_copy.setText("复制输出"))

    def _on_copy_hex(self) -> None:
        if not self._raw_output:
            self._info("输出区为空,没有可复制的内容。")
            return
        try:
            data = self._raw_output.encode("utf-8", errors="surrogateescape")
        except UnicodeEncodeError:
            # 极端情况下(未来 codec 返回非 surrogateescape 代理字符)也不崩
            data = self._raw_output.encode("utf-8", errors="surrogatepass")
        QGuiApplication.clipboard().setText(data.hex())
        self.btn_copy_hex.setText("已复制 Hex ✓")
        from PySide6.QtCore import QTimer
        QTimer.singleShot(1200, lambda: self.btn_copy_hex.setText("复制 Hex"))

    # ---------------- 一键智能解码 ----------------
    def _on_smart(self) -> None:
        text = self._get_input()
        if text is None:
            return
        self.result_tree.clear()
        from PySide6.QtWidgets import QApplication
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            hits = smart_decode(text)
        finally:
            QApplication.restoreOverrideCursor()
        if not hits:
            self._info("未能识别出有效编码。\n可尝试手动选择算法,或检查输入是否完整。")
            return
        for hit in hits:
            preview = self._display(hit.output).replace("\n", " ⏎ ")[:120]
            item = QTreeWidgetItem([" → ".join(hit.path), preview, f"{hit.score:.2f}"])
            item.setData(0, Qt.UserRole, hit.output)
            self.result_tree.addTopLevelItem(item)

    def _on_hit_double_clicked(self, item: QTreeWidgetItem, _col: int) -> None:
        out = item.data(0, Qt.UserRole)
        if out:
            self._raw_output = out
            self.output_edit.setPlainText(self._display(out))

    # ---------------- 工具 ----------------
    def _info(self, msg: str) -> None:
        QMessageBox.information(self, "MiscKit 提示", msg)

    @staticmethod
    def _display(s: str) -> str:
        """把无法显示的代理区字符逐个替换为占位符,避免界面显示异常/异常崩溃。"""
        return "".join("\ufffd" if 0xD800 <= ord(c) <= 0xDFFF else c for c in s)
