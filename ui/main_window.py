import os

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QMainWindow,
    QTabBar,
    QTabWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from core.filetype import identify
from ui.audio_panel import AudioPanel
from ui.code_panel import CodePanel
from ui.decoder_panel import DecoderPanel
from ui.file_panel import FilePanel
from ui.image_panel import ImagePanel
from ui.jwt_panel import JwtPanel
from ui.zip_panel import ZipPanel

_IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".jpe", ".gif", ".bmp",
               ".webp", ".tif", ".tiff", ".ico")
_IMAGE_KINDS = {"PNG", "JPEG", "GIF", "BMP", "WEBP", "TIFF", "ICO"}


class MainWindow(QMainWindow):
    """主窗口:模块页签 + 类似 WPS 的多文件栏。"""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("CTFusion - CTF Toolkit")
        self.resize(1200, 780)
        self.setAcceptDrops(True)
        self._active_path = ""

        self.tabs = QTabWidget()
        self.decoder_panel = DecoderPanel()
        self.file_panel = FilePanel()
        self.image_panel = ImagePanel()
        self.audio_panel = AudioPanel()
        self.zip_panel = ZipPanel()
        self.jwt_panel = JwtPanel()
        self.code_panel = CodePanel()

        self.tabs.addTab(self.decoder_panel, "编码解码")
        self.tabs.addTab(self.file_panel, "文件分析")
        self.tabs.addTab(self.image_panel, "图片隐写")
        self.tabs.addTab(self.audio_panel, "音频 LSB")
        self.tabs.addTab(self.zip_panel, "ZIP 分析")
        self.tabs.addTab(self.jwt_panel, "JWT")
        self.tabs.addTab(self.code_panel, "代码格式化")

        self.file_bar = QTabBar()
        self.file_bar.setTabsClosable(True)
        self.file_bar.setMovable(True)
        self.file_bar.setElideMode(Qt.ElideMiddle)
        self.file_bar.setExpanding(False)
        self.file_bar.currentChanged.connect(self._on_file_tab_changed)
        self.file_bar.tabCloseRequested.connect(self._close_file_tab)

        btn_add = QToolButton()
        btn_add.setText("+")
        btn_add.setToolTip("打开一个或多个文件")
        btn_add.clicked.connect(self._open_files_dialog)

        file_row = QHBoxLayout()
        file_row.setContentsMargins(0, 0, 0, 0)
        file_row.addWidget(self.file_bar, 1)
        file_row.addWidget(btn_add)

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.addLayout(file_row)
        layout.addWidget(self.tabs, 1)
        self.setCentralWidget(central)

        self._build_menu()

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("文件")
        open_action = QAction("打开文件…", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self._open_files_dialog)
        file_menu.addAction(open_action)

        close_action = QAction("关闭当前文件", self)
        close_action.setShortcut("Ctrl+W")
        close_action.triggered.connect(self._close_current_file)
        file_menu.addAction(close_action)
        file_menu.addSeparator()

        exit_action = QAction("退出", self)
        exit_action.setShortcut("Alt+F4")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

    def _open_files_dialog(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, "打开文件(可多选)")
        for path in paths:
            self.open_file(path)

    def _close_current_file(self) -> None:
        index = self.file_bar.currentIndex()
        if index >= 0:
            self._close_file_tab(index)

    # ---- 拖放:按文件类型分发到对应页签 ----
    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if path:
                self.open_file(path)

    def _detect_kind(self, path: str) -> str:
        """用文件头判断真实类型,避免扩展名写错时路由到错误页签。"""
        try:
            with open(path, "rb") as f:
                head = f.read(8192)
        except OSError:
            return ""
        return identify(head, os.path.basename(path)).real_name

    def _load_for_path(self, path: str) -> bool:
        lower = path.lower()
        kind = self._detect_kind(path)
        is_image = kind in _IMAGE_KINDS or lower.endswith(_IMAGE_EXTS)
        is_zip = kind == "ZIP" or lower.endswith(".zip")
        is_wav = kind == "WAV" or lower.endswith(".wav")
        if is_wav:
            if not self.file_panel.load_file(path):
                return False
            loaded_audio = self.audio_panel.load_file(path)
            self.tabs.setCurrentWidget(
                self.audio_panel if loaded_audio else self.file_panel)
            return loaded_audio
        if is_zip:
            if not self.file_panel.load_file(path):
                return False
            self.zip_panel.load_file(path)
            self.tabs.setCurrentWidget(self.zip_panel)
            return True
        if is_image:
            if not self.file_panel.load_file(path):
                return False
            self.image_panel.load_file(path)
            self.tabs.setCurrentWidget(self.image_panel)
            return True
        if not self.file_panel.load_file(path):
            return False
        self.tabs.setCurrentWidget(self.file_panel)
        return True

    def dispatch_file(self, path: str) -> None:
        """兼容旧接口:打开文件并加入文件栏。"""
        self.open_file(path)

    def open_file(self, path: str) -> bool:
        path = os.path.abspath(path)
        key = os.path.normcase(path)
        for index in range(self.file_bar.count()):
            existing = self.file_bar.tabData(index)
            if existing and os.path.normcase(existing) == key:
                self.file_bar.setCurrentIndex(index)
                return True
        if not self._load_for_path(path):
            return False
        label = os.path.basename(path) or path
        existing_labels = [
            self.file_bar.tabText(i) for i in range(self.file_bar.count())
        ]
        if label in existing_labels:
            label = f"{label} · {len(existing_labels) + 1}"
        index = self.file_bar.addTab(label)
        self.file_bar.setTabData(index, path)
        self.file_bar.setTabToolTip(index, path)
        self._active_path = path
        self.file_bar.setCurrentIndex(index)
        return True

    def _on_file_tab_changed(self, index: int) -> None:
        if index < 0:
            return
        path = self.file_bar.tabData(index)
        if not path or path == self._active_path:
            return
        previous = self._active_path
        if not self._load_for_path(path):
            # 用户取消(例如未保存提示)时回退到之前的页签。
            for i in range(self.file_bar.count()):
                if self.file_bar.tabData(i) == previous:
                    self.file_bar.blockSignals(True)
                    self.file_bar.setCurrentIndex(i)
                    self.file_bar.blockSignals(False)
                    break
            return
        self._active_path = path

    def _close_file_tab(self, index: int) -> None:
        if index < 0:
            return
        path = self.file_bar.tabData(index)
        if path == self._active_path and not self.file_panel._confirm_discard():
            return
        was_active = index == self.file_bar.currentIndex()
        self.file_bar.removeTab(index)
        if was_active:
            self._active_path = ""
            if self.file_bar.count():
                new_index = min(index, self.file_bar.count() - 1)
                self.file_bar.setCurrentIndex(new_index)
                # 如果 removeTab 后 currentIndex 已经是 new_index,
                # setCurrentIndex 不会发信号,这里显式加载一次。
                if not self._active_path:
                    self._on_file_tab_changed(new_index)
            else:
                self.file_panel.hex_viewer.clear()

    def closeEvent(self, event) -> None:  # noqa: N802
        if not self.file_panel._confirm_discard():
            event.ignore()
            return
        self.zip_panel.shutdown()
        super().closeEvent(event)
