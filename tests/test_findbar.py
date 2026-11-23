"""查找栏与可收缩侧边栏测试。"""

from __future__ import annotations

import os
import shutil
import sys
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication

    from ui.main_window import MainWindow
except ImportError:  # pragma: no cover
    QApplication = None  # type: ignore[assignment]
    MainWindow = None  # type: ignore[assignment]
    QTest = None  # type: ignore[assignment]


@unittest.skipUnless(QApplication is not None, "需要安装 PySide6")
class FindBarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.window = MainWindow()
        self.window.show()
        self.app.processEvents()

    def tearDown(self):
        self.window.set_language("zh_CN")
        self.window.close()

    def test_sidebar_toggle(self):
        self.assertTrue(self.window.sidebar.isVisible())
        self.window.btn_sidebar.click()
        self.assertFalse(self.window.sidebar.isVisible())
        self.window.btn_sidebar.click()
        self.assertTrue(self.window.sidebar.isVisible())

    def test_find_in_current_page(self):
        panel = self.window.decoder_panel
        self.window.tabs.setCurrentWidget(panel)
        panel.input_edit.setPlainText("hello flag{find_me} world")
        self.window._open_find()
        self.window.find_edit.setText("find_me")
        self.window._run_find(reset=True)
        self.assertGreaterEqual(len(self.window._find_matches), 1)
        self.assertIn("找到", self.window.find_status.text())
        self.assertTrue(self.window.find_status.isVisible())

    def test_find_no_result_hint(self):
        panel = self.window.decoder_panel
        self.window.tabs.setCurrentWidget(panel)
        panel.input_edit.setPlainText("hello world")
        self.window._open_find()
        self.window.find_edit.setText("does-not-exist")
        self.window._run_find(reset=True)
        self.assertIn("没有找到", self.window.find_status.text())
        self.assertIn("does-not-exist", self.window.find_status.text())

    def test_find_close(self):
        self.window._open_find()
        self.assertTrue(self.window.find_bar.isVisible())
        self.window._close_find()
        self.assertFalse(self.window.find_bar.isVisible())

    def test_save_helper_uses_writable_user_folder(self):
        from ui.save_utils import save_bytes_dialog, user_directory

        folder = Path(user_directory("image"))
        self.assertNotEqual(folder.parent, folder)
        base = ROOT / ".tmp" / f"save-{uuid.uuid4().hex}"
        base.mkdir(parents=True, exist_ok=True)
        target = base / "test.png"
        try:
            with patch(
                "ui.save_utils.QFileDialog.getSaveFileName",
                return_value=(str(target), ""),
            ):
                saved = save_bytes_dialog(
                    self.window, b"image-bytes", "test.png", "image",
                    "保存解码后的文件", "PNG (*.png)")
            self.assertEqual(saved, str(target))
            self.assertEqual(target.read_bytes(), b"image-bytes")
        finally:
            shutil.rmtree(base, ignore_errors=True)

    def test_find_keeps_keyboard_focus_while_typing(self):
        panel = self.window.decoder_panel
        self.window.tabs.setCurrentWidget(panel)
        panel.input_edit.setPlainText("alpha flag{one} beta flag{two}")
        self.window._open_find()
        QTest.keyClicks(self.window.find_edit, "flag")
        self.window._run_find(reset=True)
        self.app.processEvents()
        self.assertTrue(self.window.find_edit.hasFocus())
        QTest.keyClicks(self.window.find_edit, "x")
        self.assertEqual(self.window.find_edit.text(), "flagx")
        self.assertTrue(self.window.find_edit.hasFocus())


if __name__ == "__main__":
    unittest.main()
