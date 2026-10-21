from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QTreeWidget,
    QVBoxLayout,
    QWidget,
)


class DecoderPanel(QWidget):
    """编码自动识别 + 链式解码页签。"""

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("输入待解码内容:"))
        self.input_edit = QPlainTextEdit()
        self.input_edit.setPlaceholderText("粘贴字符串 / Hex / Base64 ...")
        self.input_edit.setMaximumHeight(140)
        layout.addWidget(self.input_edit)

        btn_row = QHBoxLayout()
        self.btn_decode = QPushButton("自动识别解码")
        self.btn_chain = QPushButton("链式爆破 (BFS)")
        btn_row.addWidget(self.btn_decode)
        btn_row.addWidget(self.btn_chain)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self.result_tree = QTreeWidget()
        self.result_tree.setHeaderLabels(["解码路径", "结果预览", "置信度"])
        layout.addWidget(self.result_tree)

        self.btn_decode.clicked.connect(self.on_decode)
        self.btn_chain.clicked.connect(self.on_chain)

    def on_decode(self) -> None:
        # TODO: 调用 core.chain.detect_all 做单层识别并填充 result_tree
        pass

    def on_chain(self) -> None:
        # TODO: 调用 core.chain.decode_chain 做 BFS 爆破并填充 result_tree
        pass
