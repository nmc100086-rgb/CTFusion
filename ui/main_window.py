import os
import time

from PySide6.QtCore import (
    QEvent,
    QObject,
    QRunnable,
    QSettings,
    QThreadPool,
    QTimer,
    Qt,
    QUrl,
    Signal,
)
from PySide6.QtGui import (
    QAction,
    QDesktopServices,
    QKeySequence,
    QShortcut,
    QTextCursor,
    QTextDocument,
)
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTabBar,
    QTabWidget,
    QTableWidget,
    QTextEdit,
    QToolButton,
    QTreeWidget,
    QVBoxLayout,
    QWidget,
)

from core import updater
from core.filetype import identify
from core.version import VERSION, __version__
from ui import first_run, i18n, save_utils
from ui.audio_panel import AudioPanel
from ui.code_panel import CodePanel
from ui.decoder_panel import DecoderPanel
from ui.file_panel import FilePanel
from ui.image_panel import ImagePanel
from ui.jwt_panel import JwtPanel
from ui.misc_panel import MiscPanel
from ui.zip_panel import ZipPanel

_IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".jpe", ".gif", ".bmp",
               ".webp", ".tif", ".tiff", ".ico")
_IMAGE_KINDS = {"PNG", "JPEG", "GIF", "BMP", "WEBP", "TIFF", "ICO"}
_UPDATE_CHECK_INTERVAL = 24 * 60 * 60


class _UpdateSignals(QObject):
    finished = Signal(object)


class _UpdateTask(QRunnable):
    def __init__(self) -> None:
        super().__init__()
        self.signals = _UpdateSignals()

    def run(self) -> None:
        try:
            info = updater.check_for_update(VERSION)
        except Exception as exc:  # 兜底：任何异常都不应影响主界面
            info = updater.UpdateInfo(current=VERSION, error=str(exc))
        self.signals.finished.emit(info)


class MainWindow(QMainWindow):
    """主窗口：分组导航 + 多文件栏 + 工具页面。"""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"CTFusion v{__version__}")
        self.resize(1200, 800)
        self.setMinimumSize(980, 680)
        self.setAcceptDrops(True)
        self._active_path = ""
        self._update_running = False
        self._update_task: _UpdateTask | None = None
        self._lang_actions: dict[str, QAction] = {}
        # 同一新版本只提示一次；同时保留内存副本，避免 QSettings 写入失败时重复提示。
        self._prompted_version = str(
            QSettings("CTFusion", "CTFusion").value(
                "update/prompted_version", "") or "")

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.tabBar().hide()

        self.decoder_panel = DecoderPanel()
        self.file_panel = FilePanel()
        self.image_panel = ImagePanel()
        self.audio_panel = AudioPanel()
        self.zip_panel = ZipPanel()
        self.misc_panel = MiscPanel()
        self.jwt_panel = JwtPanel()
        self.code_panel = CodePanel()

        for panel in (self.file_panel, self.image_panel,
                      self.audio_panel, self.zip_panel):
            panel.openRequested.connect(self.open_file)
        self.misc_panel.openFileRequested.connect(self.open_file)
        self.image_panel.qrRequested.connect(self._open_qr_for_path)
        self.file_panel.pathChanged.connect(self._on_panel_path_changed)
        self.zip_panel.pathChanged.connect(self._on_panel_path_changed)

        self.tabs.addTab(self.decoder_panel, "文本编解码")
        self.tabs.addTab(self.file_panel, "文件分析")
        self.tabs.addTab(self.image_panel, "图像分析")
        self.tabs.addTab(self.audio_panel, "音频分析")
        self.tabs.addTab(self.zip_panel, "压缩包分析")
        self.tabs.addTab(self.misc_panel, "实用工具")
        self.tabs.addTab(self.jwt_panel, "JWT 解析")
        self.tabs.addTab(self.code_panel, "代码格式化")
        self.tabs.currentChanged.connect(self._sync_navigation)

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

        self.sidebar_visible = self._load_sidebar_visible()
        self.btn_sidebar = QToolButton()
        self.btn_sidebar.setText("☰")
        self.btn_sidebar.setCheckable(True)
        self.btn_sidebar.setChecked(self.sidebar_visible)
        self.btn_sidebar.setToolButtonStyle(Qt.ToolButtonTextOnly)
        self.btn_sidebar.setFixedSize(32, 28)
        self.btn_sidebar.setToolTip("收起/展开侧边栏（Ctrl+B）")
        self.btn_sidebar.toggled.connect(self._set_sidebar_visible)

        file_row = QHBoxLayout()
        file_row.setContentsMargins(0, 0, 0, 0)
        file_row.setSpacing(6)
        file_row.addWidget(self.btn_sidebar)
        file_row.addWidget(self.file_bar, 1)
        file_row.addWidget(btn_add)

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)
        layout.addLayout(file_row)
        self.find_bar = self._build_find_bar()
        layout.addWidget(self.find_bar)

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(8)
        self.sidebar = self._build_sidebar()
        body.addWidget(self.sidebar)
        body.addWidget(self.tabs, 1)
        layout.addLayout(body, 1)
        self.setCentralWidget(central)

        self._build_menu()
        self._sync_language_controls(i18n.language())
        i18n.apply_language(self)
        self._update_sidebar_tooltip()
        self.tabs.setCurrentIndex(0)
        self._sync_navigation(0)
        if not self.sidebar_visible:
            self._set_sidebar_visible(False, persist=False)
        self._sync_sidebar_action()

        # 离屏测试环境不发起更新请求；正常桌面启动时延迟检查一次。
        if QApplication.platformName() != "offscreen":
            QTimer.singleShot(1500, self._auto_check_updates)
            # 首次运行提示只显示一次，之后由 QSettings 记住。
            QTimer.singleShot(600, self._show_first_run_tip)

    def _show_first_run_tip(self) -> None:
        try:
            first_run.maybe_show(self)
        except Exception:  # 提示失败不应影响主窗口
            pass

    # ---------------- 侧边栏 ----------------
    def _load_sidebar_visible(self) -> bool:
        settings = QSettings("CTFusion", "CTFusion")
        value = str(settings.value("ui/sidebar_visible", "true")).lower()
        return value not in ("false", "0", "no", "off")

    def _build_sidebar(self) -> QWidget:
        sidebar = QWidget()
        sidebar.setObjectName("sidePanel")
        sidebar.setFixedWidth(208)
        sidebar.setStyleSheet(
            "QWidget#sidePanel{background:#f7f8fa;"
            "border:1px solid #e1e5eb;border-radius:10px;}")
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(6, 8, 6, 8)
        layout.setSpacing(8)

        self.sidebar_title = QLabel("工具导航")
        title_font = self.sidebar_title.font()
        title_font.setBold(True)
        title_font.setPointSize(max(10, title_font.pointSize() + 1))
        self.sidebar_title.setFont(title_font)
        self.sidebar_title.setContentsMargins(4, 0, 0, 2)
        layout.addWidget(self.sidebar_title)

        self.nav = QListWidget()
        self.nav.setObjectName("toolNavigation")
        self.nav.setSpacing(2)
        self.nav.setStyleSheet(
            "QListWidget#toolNavigation{"
            "background:transparent;border:none;padding:0;outline:0;}"
            "QListWidget#toolNavigation::item{"
            "padding:8px 10px;border-radius:6px;color:#2b2f36;}"
            "QListWidget#toolNavigation::item:selected{"
            "background:#dce8ff;color:#123f8f;font-weight:600;}"
            "QListWidget#toolNavigation::item:hover{background:#e9eef7;}"
        )
        self.nav.currentRowChanged.connect(self._on_navigation_changed)

        self._nav_group("文本处理")
        self._nav_item("文本编解码", self.decoder_panel)
        self._nav_item("JWT 解析", self.jwt_panel)
        self._nav_item("代码格式化", self.code_panel)

        self._nav_group("文件与压缩包")
        self._nav_item("文件分析", self.file_panel)
        self._nav_item("压缩包分析", self.zip_panel)

        self._nav_group("图像与音频")
        self._nav_item("图像分析", self.image_panel)
        self._nav_item("音频分析", self.audio_panel)

        self._nav_group("识别与转换")
        self._nav_item("实用工具", self.misc_panel)
        layout.addWidget(self.nav, 1)

        lang_row = QHBoxLayout()
        self.language_label = QLabel("语言:")
        lang_row.addWidget(self.language_label)
        self.language_combo = QComboBox()
        for code, label in i18n.LANGUAGES:
            self.language_combo.addItem(label, code)
        self.language_combo.currentIndexChanged.connect(self._on_language_combo)
        lang_row.addWidget(self.language_combo, 1)
        layout.addLayout(lang_row)

        self.update_button = QToolButton()
        self.update_button.setText("检查更新")
        self.update_button.setToolButtonStyle(Qt.ToolButtonTextOnly)
        self.update_button.clicked.connect(lambda: self._check_updates(True))
        layout.addWidget(self.update_button)
        return sidebar

    def _set_sidebar_visible(self, visible: bool, persist: bool = True) -> None:
        self.sidebar_visible = bool(visible)
        if hasattr(self, "sidebar"):
            self.sidebar.setVisible(self.sidebar_visible)
        if hasattr(self, "btn_sidebar"):
            self.btn_sidebar.blockSignals(True)
            self.btn_sidebar.setChecked(self.sidebar_visible)
            self.btn_sidebar.blockSignals(False)
        self._update_sidebar_tooltip()
        if hasattr(self, "sidebar_action"):
            self.sidebar_action.blockSignals(True)
            self.sidebar_action.setChecked(self.sidebar_visible)
            self.sidebar_action.blockSignals(False)
        if persist:
            QSettings("CTFusion", "CTFusion").setValue(
                "ui/sidebar_visible", self.sidebar_visible)
        if not self.sidebar_visible:
            self.tabs.setFocus()

    def _sync_sidebar_action(self) -> None:
        if hasattr(self, "sidebar_action"):
            self.sidebar_action.blockSignals(True)
            self.sidebar_action.setChecked(self.sidebar_visible)
            self.sidebar_action.blockSignals(False)

    def _update_sidebar_tooltip(self) -> None:
        if not hasattr(self, "btn_sidebar"):
            return
        key = "收起/展开侧边栏（Ctrl+B）"
        self.btn_sidebar.setToolTip(i18n.tr(key))

    def _nav_group(self, label: str) -> None:
        item = QListWidgetItem(label)
        item.setFlags(Qt.NoItemFlags)
        item.setData(Qt.UserRole + 100, label)
        font = item.font()
        font.setBold(True)
        item.setFont(font)
        item.setForeground(Qt.gray)
        self.nav.addItem(item)

    def _nav_item(self, label: str, panel: QWidget) -> None:
        index = self.tabs.indexOf(panel)
        if index < 0:
            return
        item = QListWidgetItem(label)
        item.setData(Qt.UserRole, index)
        item.setData(Qt.UserRole + 100, label)
        self.nav.addItem(item)

    def _on_navigation_changed(self, row: int) -> None:
        if row < 0:
            return
        item = self.nav.item(row)
        index = item.data(Qt.UserRole) if item else None
        if isinstance(index, int) and 0 <= index < self.tabs.count():
            self.tabs.setCurrentIndex(index)

    def _sync_navigation(self, index: int) -> None:
        if not hasattr(self, "nav"):
            return
        for row in range(self.nav.count()):
            item = self.nav.item(row)
            if item and item.data(Qt.UserRole) == index:
                self.nav.blockSignals(True)
                self.nav.setCurrentRow(row)
                self.nav.blockSignals(False)
                return

    def _show_panel(self, panel: QWidget) -> None:
        index = self.tabs.indexOf(panel)
        if index >= 0:
            self.tabs.setCurrentIndex(index)

    # ---------------- 查找栏 ----------------
    def _build_find_bar(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("findBar")
        bar.setStyleSheet(
            "QFrame#findBar{background:#eef4ff;border:1px solid #cfdcf5;"
            "border-radius:9px;}"
            "QFrame#findBar QLineEdit{background:#ffffff;"
            "border:1px solid #b9c9e6;border-radius:5px;padding:5px 9px;}"
            "QFrame#findBar QPushButton{padding:4px 10px;}"
        )
        outer = QVBoxLayout(bar)
        outer.setContentsMargins(9, 6, 9, 6)
        outer.setSpacing(4)

        row = QHBoxLayout()
        row.setSpacing(6)
        self.find_label = QLabel("查找:")
        row.addWidget(self.find_label)
        self.find_edit = QLineEdit()
        self.find_edit.setPlaceholderText("在当前页面查找（不区分大小写）")
        self.find_edit.setClearButtonEnabled(True)
        self.find_edit.textChanged.connect(self._schedule_find)
        self.find_edit.returnPressed.connect(self._on_find_return)
        self.find_edit.installEventFilter(self)
        row.addWidget(self.find_edit, 1)

        self.find_prev_button = QPushButton("上一个")
        self.find_prev_button.setFocusPolicy(Qt.NoFocus)
        self.find_prev_button.clicked.connect(lambda: self._find_step(-1))
        row.addWidget(self.find_prev_button)
        self.find_next_button = QPushButton("下一个")
        self.find_next_button.setFocusPolicy(Qt.NoFocus)
        self.find_next_button.clicked.connect(lambda: self._find_step(1))
        row.addWidget(self.find_next_button)
        self.find_close_button = QPushButton("关闭")
        self.find_close_button.setFocusPolicy(Qt.NoFocus)
        self.find_close_button.clicked.connect(self._close_find)
        row.addWidget(self.find_close_button)
        outer.addLayout(row)

        self.find_status = QLabel("")
        self.find_status.setWordWrap(True)
        self.find_status.hide()
        outer.addWidget(self.find_status)

        self._find_matches: list[tuple] = []
        self._find_index = -1
        self._find_query = ""
        self._find_panel: QWidget | None = None
        self._find_no_content = False
        self._find_timer = QTimer(self)
        self._find_timer.setSingleShot(True)
        self._find_timer.setInterval(160)
        self._find_timer.timeout.connect(lambda: self._run_find(reset=True))
        self.find_bar = bar
        bar.hide()
        return bar

    def _open_find(self) -> None:
        focus = QApplication.focusWidget()
        hex_viewer = getattr(self.file_panel, "hex_viewer", None)
        if hex_viewer is not None and focus is not None:
            if focus is hex_viewer or hex_viewer.isAncestorOf(focus):
                hex_viewer.search_edit.setFocus()
                hex_viewer.search_edit.selectAll()
                return
        self.find_bar.show()
        self.find_edit.setFocus()
        self.find_edit.selectAll()
        if self.find_edit.text().strip():
            self._run_find(reset=True)

    def _close_find(self) -> None:
        self._find_timer.stop()
        self.find_bar.hide()
        self._find_matches = []
        self._find_index = -1
        self._find_query = ""
        self._find_panel = None
        self.find_edit.clear()
        self.find_status.clear()
        self.find_status.hide()
        self.tabs.setFocus()

    def _schedule_find(self) -> None:
        if not self.find_bar.isVisible():
            return
        query = self.find_edit.text().strip()
        if not query:
            self._find_timer.stop()
            self._find_matches = []
            self._find_index = -1
            self._find_query = ""
            self.find_status.clear()
            self.find_status.hide()
            return
        self._find_timer.start()

    def _on_find_return(self) -> None:
        if not self.find_bar.isVisible():
            self._open_find()
            return
        query = self.find_edit.text().strip()
        panel = self.tabs.currentWidget()
        if (query != self._find_query or panel is not self._find_panel
                or not self._find_matches):
            self._run_find(reset=True)
        else:
            self._find_step(1)

    def _run_find(self, reset: bool = False) -> None:
        query = self.find_edit.text().strip()
        panel = self.tabs.currentWidget()
        if not query or panel is None:
            self.find_status.hide()
            return
        if (reset or query != self._find_query
                or panel is not self._find_panel):
            self._find_matches = self._collect_find_matches(query, panel)
            self._find_query = query
            self._find_panel = panel
            self._find_index = -1
        if not self._find_matches:
            if self._find_no_content:
                self._show_find_status(
                    i18n.tr("当前页面没有可搜索的文本内容。请先打开文件，"
                            "或切换到文本/表格页签。"), "warn")
            else:
                self._show_find_status(
                    i18n.tr("没有找到“{query}”。可以试试：换一个关键词、"
                            "检查拼写，或切换到包含文本的页签。").format(
                                query=query), "warn")
            return
        self._find_index = (self._find_index + 1) % len(self._find_matches)
        self._apply_find_match(self._find_matches[self._find_index])
        self._show_find_status(
            i18n.tr("找到 {count} 个结果，当前 {index} / {count}").format(
                count=len(self._find_matches), index=self._find_index + 1),
            "ok")

    def _find_step(self, delta: int) -> None:
        query = self.find_edit.text().strip()
        panel = self.tabs.currentWidget()
        if (not self._find_matches or query != self._find_query
                or panel is not self._find_panel):
            self._run_find(reset=True)
            return
        self._find_index = (self._find_index + delta) % len(self._find_matches)
        self._apply_find_match(self._find_matches[self._find_index])
        self._show_find_status(
            i18n.tr("找到 {count} 个结果，当前 {index} / {count}").format(
                count=len(self._find_matches), index=self._find_index + 1),
            "ok")

    def _collect_find_matches(self, query: str, panel: QWidget) -> list[tuple]:
        needle = query.casefold()
        matches: list[tuple] = []
        limit = 5000
        self._find_no_content = not self._has_searchable_text(panel)

        editors = list(panel.findChildren(QPlainTextEdit))
        editors.extend(panel.findChildren(QTextEdit))
        for edit in editors:
            if edit is self.find_edit or not edit.isVisibleTo(panel):
                continue
            document = edit.document()
            cursor = QTextCursor(document)
            while len(matches) < limit:
                cursor = document.find(query, cursor)
                if cursor.isNull():
                    break
                matches.append(("text", edit, cursor.selectionStart(),
                                cursor.selectionEnd()))
            if len(matches) >= limit:
                break

        if len(matches) < limit:
            for table in panel.findChildren(QTableWidget):
                if not table.isVisibleTo(panel):
                    continue
                for row in range(table.rowCount()):
                    for column in range(table.columnCount()):
                        item = table.item(row, column)
                        if item and needle in item.text().casefold():
                            matches.append(("table", table, row, column))
                            if len(matches) >= limit:
                                break
                    if len(matches) >= limit:
                        break
                if len(matches) >= limit:
                    break

        if len(matches) < limit:
            for tree in panel.findChildren(QTreeWidget):
                if not tree.isVisibleTo(panel):
                    continue
                stack = [tree.topLevelItem(i) for i in range(tree.topLevelItemCount())]
                while stack and len(matches) < limit:
                    item = stack.pop()
                    if item is None:
                        continue
                    for column in range(item.columnCount()):
                        if needle in item.text(column).casefold():
                            matches.append(("tree", tree, item, column))
                            break
                    stack.extend(item.child(i) for i in range(item.childCount()))

        return matches

    @staticmethod
    def _has_searchable_text(panel: QWidget) -> bool:
        for edit in panel.findChildren(QPlainTextEdit):
            if edit.isVisibleTo(panel):
                return True
        for edit in panel.findChildren(QTextEdit):
            if edit.isVisibleTo(panel):
                return True
        for table in panel.findChildren(QTableWidget):
            if table.isVisibleTo(panel) and table.rowCount():
                return True
        for tree in panel.findChildren(QTreeWidget):
            if tree.isVisibleTo(panel) and tree.topLevelItemCount():
                return True
        return False

    def _apply_find_match(self, match: tuple) -> None:
        # 关键：查找时不要抢走查找框的焦点，否则每输入一个字符都要重新点
        # 一次输入框。若用户原本就在查找框里，应用结果后把焦点还回去。
        keep_find_focus = self.find_edit.hasFocus()
        kind = match[0]
        if kind == "text":
            _, edit, start, end = match
            cursor = QTextCursor(edit.document())
            cursor.setPosition(start)
            cursor.setPosition(end, QTextCursor.KeepAnchor)
            edit.setTextCursor(cursor)
            edit.ensureCursorVisible()
        elif kind == "table":
            _, table, row, column = match
            table.setCurrentCell(row, column)
            item = table.item(row, column)
            if item is not None:
                table.scrollToItem(item)
        else:
            _, tree, item, column = match
            parent = item.parent()
            while parent is not None:
                parent.setExpanded(True)
                parent = parent.parent()
            tree.setCurrentItem(item, column)
            tree.scrollToItem(item)
        if keep_find_focus:
            self.find_edit.setFocus()

    def _show_find_status(self, text: str, kind: str = "info") -> None:
        colors = {"ok": "#166534", "warn": "#92400e", "info": "#1e3a8a"}
        backgrounds = {"ok": "#f0fdf4", "warn": "#fffbeb", "info": "#eff6ff"}
        self.find_status.setStyleSheet(
            f"color:{colors.get(kind, colors['info'])};"
            f"background:{backgrounds.get(kind, backgrounds['info'])};"
            "border:1px solid #dbe4f0;border-radius:5px;padding:4px 7px;")
        self.find_status.setText(text)
        self.find_status.show()

    def eventFilter(self, obj, event) -> bool:  # noqa: N802
        if (obj is self.find_edit and event.type() == QEvent.KeyPress
                and event.key() == Qt.Key_Escape):
            self._close_find()
            return True
        return super().eventFilter(obj, event)

    # ---------------- 菜单 ----------------
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

        properties_action = QAction("查看文件属性…", self)
        properties_action.setShortcut("Alt+Return")
        properties_action.triggered.connect(self._show_file_properties)
        file_menu.addAction(properties_action)
        file_menu.addSeparator()

        exit_action = QAction("退出", self)
        exit_action.setShortcut("Alt+F4")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        view_menu = self.menuBar().addMenu("视图")
        self.sidebar_action = QAction("显示侧边栏", self)
        self.sidebar_action.setCheckable(True)
        self.sidebar_action.setChecked(self.sidebar_visible)
        self.sidebar_action.setShortcut("Ctrl+B")
        self.sidebar_action.toggled.connect(self._set_sidebar_visible)
        view_menu.addAction(self.sidebar_action)
        self.find_action = QAction("查找当前页面", self)
        self.find_action.setShortcut(QKeySequence.Find)
        self.find_action.triggered.connect(self._open_find)
        view_menu.addAction(self.find_action)
        view_menu.addSeparator()

        settings_menu = self.menuBar().addMenu("设置")
        language_menu = settings_menu.addMenu("语言")
        for code, label in i18n.LANGUAGES:
            action = QAction(label, self)
            action.setCheckable(True)
            action.triggered.connect(
                lambda _checked=False, c=code: self.set_language(c))
            language_menu.addAction(action)
            self._lang_actions[code] = action
        settings_menu.addSeparator()
        check_action = QAction("检查更新…", self)
        check_action.triggered.connect(lambda: self._check_updates(True))
        settings_menu.addAction(check_action)
        admin_action = QAction("以管理员身份重新启动", self)
        admin_action.setToolTip(
            "以管理员权限重新打开程序，可写入任何 Windows 允许的位置")
        admin_action.triggered.connect(self._restart_as_admin)
        settings_menu.addAction(admin_action)

        help_menu = self.menuBar().addMenu("帮助")
        diagnose_action = QAction("保存权限自检…", self)
        diagnose_action.setToolTip("检查桌面/文档/图片/下载/程序目录能否正常写入")
        diagnose_action.triggered.connect(
            lambda: save_utils.show_diagnose_dialog(self))
        help_menu.addAction(diagnose_action)
        log_action = QAction("打开保存日志", self)
        log_action.triggered.connect(self._open_save_log)
        help_menu.addAction(log_action)
        help_menu.addSeparator()
        about_action = QAction("关于", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _open_save_log(self) -> None:
        path = save_utils.ensure_log_file()
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _restart_as_admin(self) -> None:
        if save_utils.is_admin():
            QMessageBox.information(
                self, "CTFusion", "当前已经是管理员权限，可以直接保存到任何位置。")
            return
        from core import elevate

        ok, error = elevate.relaunch_elevated()
        if not ok:
            QMessageBox.warning(
                self, "CTFusion",
                f"无法以管理员身份重新启动：\n{error}")
            return
        if self.close():
            QApplication.quit()

    def _show_about(self) -> None:
        role = "管理员" if save_utils.is_admin() else "普通用户"
        QMessageBox.information(
            self, "CTFusion",
            f"CTFusion v{__version__}\n\n"
            "本地 CTF 综合分析工具箱。\n"
            f"当前权限：{role}\n"
            f"保存日志：{save_utils.log_file()}\n\n"
            "更新地址：\n"
            "https://github.com/nmc100086-rgb/CTFusion")

    # ---------------- 语言 ----------------
    def _on_language_combo(self, index: int) -> None:
        code = self.language_combo.itemData(index)
        if code and code != i18n.language():
            self.set_language(str(code))

    def set_language(self, code: str) -> None:
        i18n.set_language(code)
        i18n.apply_language(self)
        self._sync_language_controls(code)
        self.decoder_panel.retranslate()
        self._update_sidebar_tooltip()
        self._sync_navigation(self.tabs.currentIndex())

    def _sync_language_controls(self, code: str) -> None:
        index = self.language_combo.findData(code)
        if index >= 0 and self.language_combo.currentIndex() != index:
            self.language_combo.blockSignals(True)
            self.language_combo.setCurrentIndex(index)
            self.language_combo.blockSignals(False)
        for action_code, action in self._lang_actions.items():
            action.setChecked(action_code == code)

    # ---------------- 更新 ----------------
    def _auto_check_updates(self) -> None:
        settings = QSettings("CTFusion", "CTFusion")
        try:
            last = float(settings.value("update/last_check", 0) or 0)
        except (TypeError, ValueError):
            last = 0.0
        if time.time() - last < _UPDATE_CHECK_INTERVAL:
            return
        self._check_updates(False)

    def _check_updates(self, manual: bool) -> None:
        if self._update_running:
            if manual:
                QMessageBox.information(
                    self, "CTFusion", "正在检查更新，请稍候。")
            return
        self._update_running = True
        self.update_button.setEnabled(False)
        self.update_button.setText("正在检查更新…")
        task = _UpdateTask()
        task.signals.finished.connect(
            lambda info, m=manual: self._on_update_checked(info, m))
        self._update_task = task
        QThreadPool.globalInstance().start(task)

    def _on_update_checked(self, info, manual: bool) -> None:
        self._update_running = False
        self._update_task = None
        self.update_button.setEnabled(True)
        self.update_button.setText("检查更新")
        settings = QSettings("CTFusion", "CTFusion")
        settings.setValue("update/last_check", time.time())
        if getattr(info, "available", False):
            latest = ".".join(str(x) for x in info.latest) if info.latest else ""
            # 同一个新版本只在第一次发现时提示，避免每次运行都弹窗。
            if (not manual and latest
                    and latest in (self._prompted_version,
                                   str(settings.value(
                                       "update/prompted_version", "")))):
                return
            if latest:
                self._prompted_version = latest
                settings.setValue("update/prompted_version", latest)
            self._show_update_prompt(info)
            return
        if not manual:
            return
        if getattr(info, "error", ""):
            QMessageBox.warning(
                self, "检查更新失败",
                f"检查更新失败：{info.error}\n\n"
                "请确认网络连接正常，或稍后再试。")
            return
        QMessageBox.information(
            self, "CTFusion",
            f"当前已是最新版本（v{__version__}）。")

    def _show_update_prompt(self, info) -> None:
        box = QMessageBox(self)
        box.setWindowTitle(i18n.tr("发现新版本"))
        box.setText(i18n.tr(
            "发现新版本，请到github官网更新，"
            "https://github.com/nmc100086-rgb/CTFusion"))
        latest = ".".join(str(x) for x in info.latest) if info.latest else "—"
        box.setInformativeText(
            f"{i18n.tr('当前版本')}: v{__version__}\n"
            f"{i18n.tr('最新版本')}: v{latest}")
        open_button = box.addButton(
            i18n.tr("打开 GitHub"), QMessageBox.AcceptRole)
        box.addButton(i18n.tr("稍后"), QMessageBox.RejectRole)
        box.exec()
        if box.clickedButton() is open_button:
            QDesktopServices.openUrl(QUrl(updater.REPOSITORY_URL))

    # ---------------- 文件 ----------------
    def _open_files_dialog(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, "打开文件(可多选)")
        for path in paths:
            self.open_file(path)

    def _close_current_file(self) -> None:
        index = self.file_bar.currentIndex()
        if index >= 0:
            self._close_file_tab(index)

    def _show_file_properties(self) -> None:
        if not self._active_path:
            QMessageBox.information(
                self, "CTFusion",
                "请先打开一个文件；文件属性会显示路径、时间、权限、类型和哈希。")
            return
        self._show_panel(self.file_panel)
        self.file_panel.show_properties()

    def _open_qr_for_path(self, path: str) -> None:
        if not path:
            return
        self._show_panel(self.misc_panel)
        self.misc_panel.tabs.setCurrentWidget(self.misc_panel.qr_tab)
        self.misc_panel.qr_tab.load_file(path)

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
            if not self.zip_panel.clear():
                return False
            self.image_panel.clear()
            loaded_audio = self.audio_panel.load_file(path)
            self._show_panel(
                self.audio_panel if loaded_audio else self.file_panel)
            return loaded_audio
        if is_zip:
            if not self.file_panel.load_file(path):
                return False
            self.image_panel.clear()
            self.audio_panel.clear()
            if not self.zip_panel.clear():
                return False
            if not self.zip_panel.load_file(path):
                return False
            self._show_panel(self.zip_panel)
            return True
        if is_image:
            if not self.file_panel.load_file(path):
                return False
            self.audio_panel.clear()
            if not self.zip_panel.clear():
                return False
            if not self.image_panel.load_file(path):
                return False
            self._show_panel(self.image_panel)
            return True
        if not self.file_panel.load_file(path):
            return False
        self.image_panel.clear()
        self.audio_panel.clear()
        if not self.zip_panel.clear():
            return False
        self._show_panel(self.file_panel)
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
                self.file_panel.clear()
                self.image_panel.clear()
                self.audio_panel.clear()
                self.zip_panel.clear()

    def _on_panel_path_changed(self, old_path: str, new_path: str) -> None:
        if not new_path:
            return
        for index in range(self.file_bar.count()):
            tab_path = self.file_bar.tabData(index)
            if (tab_path and old_path
                    and os.path.normcase(tab_path) == os.path.normcase(old_path)):
                self.file_bar.setTabText(index, os.path.basename(new_path))
                self.file_bar.setTabData(index, new_path)
                self.file_bar.setTabToolTip(index, new_path)
                self._active_path = new_path
                return

    def closeEvent(self, event) -> None:  # noqa: N802
        if not self.file_panel._confirm_discard():
            event.ignore()
            return
        if not self.file_panel.shutdown() or not self.zip_panel.shutdown():
            QMessageBox.warning(
                self, "CTFusion",
                "后台任务仍在停止中,请稍后再关闭程序。")
            event.ignore()
            return
        super().closeEvent(event)
