from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget


class ZipPanel(QWidget):
    """ZIP 伪加密修复 / CRC32 爆破 / 字典爆破页签。"""

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        self.info_label = QLabel("拖入 ZIP 文件开始分析")
        layout.addWidget(self.info_label)
        layout.addStretch()
        # TODO: 压缩包结构列表 / 伪加密标志 / 爆破进度

    def load_file(self, path: str) -> None:
        # TODO: 调用 core.zipcrack 解析压缩包结构
        self.info_label.setText(f"已载入: {path}")
