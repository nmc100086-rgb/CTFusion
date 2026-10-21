from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget


class StegoPanel(QWidget):
    """文件分析 + 图片隐写页签。"""

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        self.info_label = QLabel("拖入图片或任意文件开始分析")
        layout.addWidget(self.info_label)
        layout.addStretch()
        # TODO: 文件类型识别结果 / Hex 查看器 / 位平面视图 / EXIF 表格

    def load_file(self, path: str) -> None:
        # TODO: 调用 core.filetype 识别真实类型并展示结构信息
        self.info_label.setText(f"已载入: {path}")
