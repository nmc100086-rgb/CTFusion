from PySide6.QtWidgets import QMainWindow, QTabWidget

from ui.decoder_panel import DecoderPanel
from ui.file_panel import FilePanel
from ui.image_panel import ImagePanel
from ui.zip_panel import ZipPanel

_IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".jpe", ".gif", ".bmp",
               ".webp", ".tif", ".tiff", ".ico")


class MainWindow(QMainWindow):
    """主窗口:四个功能页签,支持拖入文件自动分发。"""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("MiscKit - CTF Misc 工具箱")
        self.resize(1100, 720)
        self.setAcceptDrops(True)

        self.tabs = QTabWidget()
        self.decoder_panel = DecoderPanel()
        self.file_panel = FilePanel()
        self.image_panel = ImagePanel()
        self.zip_panel = ZipPanel()

        self.tabs.addTab(self.decoder_panel, "编码解码")
        self.tabs.addTab(self.file_panel, "文件分析")
        self.tabs.addTab(self.image_panel, "图片隐写")
        self.tabs.addTab(self.zip_panel, "ZIP 破解")
        self.setCentralWidget(self.tabs)

    # ---- 拖放:按文件类型分发到对应页签 ----
    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if path:
                self.dispatch_file(path)
                break

    def dispatch_file(self, path: str) -> None:
        lower = path.lower()
        if lower.endswith((".zip", ".rar", ".7z")):
            self.tabs.setCurrentWidget(self.zip_panel)
            self.zip_panel.load_file(path)
        elif lower.endswith(_IMAGE_EXTS):
            # 图片同时载入文件分析页,方便做 Hex/结构检查
            self.file_panel.load_file(path)
            self.image_panel.load_file(path)
            self.tabs.setCurrentWidget(self.image_panel)
        else:
            self.file_panel.load_file(path)
            self.tabs.setCurrentWidget(self.file_panel)
