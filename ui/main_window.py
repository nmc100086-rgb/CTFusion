from PySide6.QtWidgets import QMainWindow, QTabWidget

from ui.decoder_panel import DecoderPanel
from ui.stego_panel import StegoPanel
from ui.zip_panel import ZipPanel


class MainWindow(QMainWindow):
    """主窗口：三个功能页签，支持拖入文件自动分发。"""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("MiscKit - CTF Misc 工具箱")
        self.resize(1100, 720)
        self.setAcceptDrops(True)

        self.tabs = QTabWidget()
        self.decoder_panel = DecoderPanel()
        self.stego_panel = StegoPanel()
        self.zip_panel = ZipPanel()

        self.tabs.addTab(self.decoder_panel, "编码解码")
        self.tabs.addTab(self.stego_panel, "文件分析 / 图片隐写")
        self.tabs.addTab(self.zip_panel, "ZIP 破解")
        self.setCentralWidget(self.tabs)

    # ---- 拖放：按文件类型分发到对应页签 ----
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
        else:
            self.tabs.setCurrentWidget(self.stego_panel)
            self.stego_panel.load_file(path)
