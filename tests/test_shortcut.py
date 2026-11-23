"""Ctrl+F / Ctrl+B 快捷键冒烟测试。"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication

    from ui.main_window import MainWindow
except ImportError:  # pragma: no cover
    QApplication = None  # type: ignore[assignment]
    MainWindow = None  # type: ignore[assignment]
    QTest = None  # type: ignore[assignment]
    Qt = None  # type: ignore[assignment]


@unittest.skipUnless(QApplication is not None, "需要安装 PySide6")
class ShortcutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.window = MainWindow()
        self.window.show()
        self.app.processEvents()

    def tearDown(self):
        self.window.close()

    def test_ctrl_f_opens_find_bar(self):
        self.window.tabs.setCurrentWidget(self.window.decoder_panel)
        QTest.keyClick(self.window, Qt.Key_F, Qt.ControlModifier)
        self.app.processEvents()
        self.assertTrue(self.window.find_bar.isVisible())
        self.assertTrue(self.window.find_edit.hasFocus())

    def test_ctrl_b_toggles_sidebar(self):
        visible = self.window.sidebar.isVisible()
        QTest.keyClick(self.window, Qt.Key_B, Qt.ControlModifier)
        self.app.processEvents()
        self.assertNotEqual(self.window.sidebar.isVisible(), visible)


if __name__ == "__main__":
    unittest.main()
