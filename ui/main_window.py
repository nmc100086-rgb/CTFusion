import os

from PySide6.QtWidgets import QMainWindow, QTabWidget

from core.filetype import identify
from ui.audio_panel import AudioPanel
from ui.decoder_panel import DecoderPanel
from ui.file_panel import FilePanel
from ui.image_panel import ImagePanel
from ui.zip_panel import ZipPanel

_IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".jpe", ".gif", ".bmp",
               ".webp", ".tif", ".tiff", ".ico")
_IMAGE_KINDS = {"PNG", "JPEG", "GIF", "BMP", "WEBP", "TIFF", "ICO"}


class MainWindow(QMainWindow):
    """主窗口:五个功能页签,支持拖入文件自动分发。"""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("MiscKit - CTF Misc 工具箱")
        self.resize(1100, 720)
        self.setAcceptDrops(True)

        self.tabs = QTabWidget()
        self.decoder_panel = DecoderPanel()
        self.file_panel = FilePanel()
        self.image_panel = ImagePanel()
        self.audio_panel = AudioPanel()
        self.zip_panel = ZipPanel()

        self.tabs.addTab(self.decoder_panel, "编码解码")
        self.tabs.addTab(self.file_panel, "文件分析")
        self.tabs.addTab(self.image_panel, "图片隐写")
        self.tabs.addTab(self.audio_panel, "音频 LSB")
        self.tabs.addTab(self.zip_panel, "ZIP 分析")
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

    def _detect_kind(self, path: str) -> str:
        """用文件头判断真实类型,避免扩展名写错时路由到错误页签。"""
        try:
            with open(path, "rb") as f:
                head = f.read(8192)
        except OSError:
            return ""
        return identify(head, os.path.basename(path)).real_name

    def dispatch_file(self, path: str) -> None:
        lower = path.lower()
        kind = self._detect_kind(path)
        is_image = kind in _IMAGE_KINDS or lower.endswith(_IMAGE_EXTS)
        is_zip = kind == "ZIP" or lower.endswith(".zip")
        is_wav = kind == "WAV" or lower.endswith(".wav")
        if is_wav:
            if self.file_panel.load_file(path):
                loaded_audio = self.audio_panel.load_file(path)
                self.tabs.setCurrentWidget(
                    self.audio_panel if loaded_audio else self.file_panel)
        elif is_zip:
            # ZIP 页签目前是基础分析页,文件分析页同时也载入,避免丢失 Hex/结构视图。
            loaded = self.file_panel.load_file(path)
            if not loaded:
                return
            self.zip_panel.load_file(path)
            self.tabs.setCurrentWidget(self.zip_panel)
        elif is_image:
            # 图片同时载入文件分析页,方便做 Hex/结构检查
            loaded = self.file_panel.load_file(path)
            if not loaded:
                return
            self.image_panel.load_file(path)
            self.tabs.setCurrentWidget(self.image_panel)
        else:
            if self.file_panel.load_file(path):
                self.tabs.setCurrentWidget(self.file_panel)

    def closeEvent(self, event) -> None:  # noqa: N802
        if not self.file_panel._confirm_discard():
            event.ignore()
            return
        super().closeEvent(event)
