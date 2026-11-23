"""多语言界面冒烟测试。"""

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
    from PySide6.QtWidgets import QApplication

    from ui import i18n
    from ui.main_window import MainWindow
except ImportError:  # pragma: no cover
    QApplication = None  # type: ignore[assignment]
    i18n = None  # type: ignore[assignment]
    MainWindow = None  # type: ignore[assignment]


@unittest.skipUnless(QApplication is not None, "需要安装 PySide6")
class I18nUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.window = MainWindow()

    def tearDown(self):
        self.window.set_language("zh_CN")
        self.window.close()

    def test_english_static_ui(self):
        self.window.set_language("en")
        labels = [self.window.tabs.tabText(i)
                  for i in range(self.window.tabs.count())]
        self.assertEqual(labels[0], "Text Codec")
        self.assertEqual(labels[2], "Image Analysis")
        self.assertEqual(labels[5], "Utilities")
        self.assertEqual(self.window.menuBar().actions()[0].text(), "File")
        self.assertEqual(self.window.file_panel.tabs.tabText(0), "Overview")
        self.assertEqual(self.window.image_panel.tabs.tabText(0), "Basic Info")
        self.assertEqual(self.window.misc_panel.qr_tab.btn_open.text(),
                         "Open Image…")

    def test_switching_major_languages(self):
        for code in ("ja", "ko", "es", "fr", "de", "ru", "pt", "ar"):
            self.window.set_language(code)
            self.assertNotEqual(self.window.tabs.tabText(0), "文本编解码")
            self.assertTrue(self.window.tabs.tabText(0))
        self.window.set_language("zh_CN")
        self.assertEqual(self.window.tabs.tabText(0), "文本编解码")
        self.assertEqual(self.window.tabs.tabText(5), "实用工具")

    def test_language_state(self):
        self.window.set_language("fr")
        self.assertEqual(i18n.language(), "fr")
        self.window.set_language("zh_CN")
        self.assertEqual(i18n.language(), "zh_CN")


if __name__ == "__main__":
    unittest.main()
