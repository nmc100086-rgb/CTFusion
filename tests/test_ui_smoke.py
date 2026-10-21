"""MiscKit 编码/解码页签的离屏冒烟测试。

运行方式(在 MiscKit 目录下):
    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import base64
import os
import sys
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from PySide6.QtWidgets import QApplication, QCheckBox, QComboBox, QLineEdit

    from ui.main_window import MainWindow
except ImportError:  # pragma: no cover - 没装 PySide6 时跳过
    QApplication = None  # type: ignore[assignment]
    QCheckBox = None  # type: ignore[assignment]
    QComboBox = None  # type: ignore[assignment]
    QLineEdit = None  # type: ignore[assignment]
    MainWindow = None  # type: ignore[assignment]


@unittest.skipUnless(QApplication is not None, "需要安装 PySide6")
class DecoderPanelSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.window = MainWindow()
        self.panel = self.window.decoder_panel
        self.messages: list[str] = []
        self.panel._info = self.messages.append

    def tearDown(self):
        self.window.close()

    def select(self, name: str) -> None:
        for i in range(self.panel.combo.count()):
            if self.panel.combo.itemData(i).name == name:
                self.panel.combo.setCurrentIndex(i)
                return
        self.fail(f"找不到 codec: {name}")

    def test_cycle_all_codecs(self):
        for i in range(self.panel.combo.count()):
            self.panel.combo.setCurrentIndex(i)
        self.assertGreater(self.panel.combo.count(), 30)

    def test_switching_codec_clears_stale_alphabet(self):
        self.select("Base16")
        self.panel.alphabet_edit.setText("0123456789ABCDEF")
        self.panel.input_edit.setPlainText("A")
        self.panel._on_encode()
        self.assertEqual(self.panel.output_edit.toPlainText(), "41")

        self.select("Base32")
        self.assertEqual(self.panel.alphabet_edit.text(), "")
        self.panel.input_edit.setPlainText("A")
        self.panel._on_encode()
        self.assertEqual(self.panel.output_edit.toPlainText(), "IE======")

    def test_ascii_surrogate_does_not_crash(self):
        self.select("ASCII 码")
        self.panel.input_edit.setPlainText("55296")
        self.panel._on_decode()
        self.assertTrue(any("代理区" in msg for msg in self.messages))

    def test_binary_output_and_hex_copy(self):
        self.select("Base16")
        self.panel.input_edit.setPlainText("ff")
        self.panel._on_decode()
        self.assertEqual(self.panel._raw_output, "\udcff")
        self.assertEqual(self.panel.output_edit.toPlainText(), "\ufffd")

        self.panel._on_copy_hex()
        self.assertEqual(QApplication.clipboard().text(), "ff")

    def test_smart_decode_plain_text_has_no_rows(self):
        self.panel.input_edit.setPlainText("HelloWorld")
        self.panel._on_smart()
        self.assertEqual(self.panel.result_tree.topLevelItemCount(), 0)
        self.assertTrue(any("未能识别" in msg for msg in self.messages))

    def test_smart_decode_flag_row_and_double_click(self):
        encoded = base64.b64encode(b"flag{ui_smart}").decode()
        self.panel.input_edit.setPlainText(encoded)
        self.panel._on_smart()
        self.assertEqual(self.panel.result_tree.topLevelItemCount(), 1)
        item = self.panel.result_tree.topLevelItem(0)
        self.assertEqual(item.text(0), "Base64")
        self.panel._on_hit_double_clicked(item, 0)
        self.assertEqual(self.panel.output_edit.toPlainText(), "flag{ui_smart}")
        self.assertEqual(self.panel._raw_output, "flag{ui_smart}")

    def test_new_parameter_rows(self):
        self.select("AES")
        for name in ("mode", "padding", "format", "key_format", "iv_format"):
            self.assertIsInstance(self.panel._param_edits[name], QComboBox)
        self.assertFalse(self.panel.btn_gen_key.isHidden())
        self.assertFalse(self.panel.btn_gen_iv.isHidden())
        self.select("RC4")
        for name in ("plaintext_format", "format", "key_format"):
            self.assertIsInstance(self.panel._param_edits[name], QComboBox)
        self.assertFalse(self.panel.btn_gen_key.isHidden())
        self.select("Hill 密码")
        self.assertTrue(self.panel.btn_gen_key.isHidden())
        self.select("Hill 密码")
        for name in ("char_mode", "mode", "restore", "strip_padding"):
            self.assertIsInstance(self.panel._param_edits[name], QComboBox)
        self.select("曲路密码")
        self.assertIn("cols", self.panel._param_edits)
        self.select("栅栏密码")
        self.assertIsInstance(self.panel._param_edits["fence_type"], QComboBox)
        self.assertIsInstance(self.panel._param_edits["rails"], QLineEdit)
        self.select("摩斯电码")
        self.assertIsInstance(self.panel._param_edits["letter_case"], QComboBox)
        self.assertIsInstance(self.panel._param_edits["restore_spaces"], QComboBox)
        self.select("猪圈密码")
        self.assertIsInstance(self.panel._param_edits["separator"], QComboBox)
        self.assertIsInstance(self.panel._param_edits["keep_nonletters"], QCheckBox)

    def test_md5_ui(self):
        self.select("MD5")
        self.assertFalse(self.panel.btn_decode.isEnabled())
        self.panel.input_edit.setPlainText("flag{welcome come to ctf}")
        self.panel._on_encode()
        self.assertEqual(
            self.panel.output_edit.toPlainText(),
            "MD5-16 位小写: 4fb23af40142ec75\n"
            "MD5-16 位大写: 4FB23AF40142EC75\n"
            "MD5-32 位小写: d46927f94fb23af40142ec75dac57186\n"
            "MD5-32 位大写: D46927F94FB23AF40142EC75DAC57186",
        )

    def test_aes_ui_generation_and_iv_state(self):
        self.select("AES")
        self.assertFalse(self.panel.iv_edit.isEnabled())  # 默认 ECB
        self.assertFalse(self.panel._param_edits["iv_format"].isEnabled())

        self.panel._generate_key()
        self.assertEqual(len(self.panel.key_edit.text()), 16)

        mode = self.panel._param_edits["mode"]
        mode.setCurrentIndex(mode.findData("CBC"))
        self.assertTrue(self.panel.iv_edit.isEnabled())
        self.assertTrue(self.panel._param_edits["iv_format"].isEnabled())
        self.panel._generate_iv()
        self.assertEqual(len(self.panel.iv_edit.text()), 16)

        self.panel.input_edit.setPlainText("Hello, World!")
        self.panel._on_encode()
        ct = self.panel.output_edit.toPlainText()
        self.panel.input_edit.setPlainText(ct)
        self.panel._on_decode()
        self.assertEqual(self.panel.output_edit.toPlainText(), "Hello, World!")

        # 切回 ECB 后 IV 被禁用并清空
        mode.setCurrentIndex(mode.findData("ECB"))
        self.assertFalse(self.panel.iv_edit.isEnabled())
        self.assertEqual(self.panel.iv_edit.text(), "")

    def test_rc4_ui_plaintext_formats(self):
        self.select("RC4")
        self.panel.key_edit.setText("deadbeef")
        plain_widget = self.panel._param_edits["plaintext_format"]
        plain_widget.setCurrentIndex(plain_widget.findData("hex"))
        self.panel.input_edit.setPlainText("48656c6c6f2c20576f726c6421")
        self.panel._on_encode()
        ct = self.panel.output_edit.toPlainText()
        self.assertTrue(ct)
        self.panel.input_edit.setPlainText(ct)
        self.panel._on_decode()
        self.assertEqual(self.panel.output_edit.toPlainText(),
                         "48656c6c6f2c20576f726c6421")

    def test_zero_width_ui_cover(self):
        self.select("零宽字符")
        self.panel._param_edits["cover"].setText("hello world")
        self.panel.input_edit.setPlainText("flag{zero_width}")
        self.panel._on_encode()
        encoded = self.panel.output_edit.toPlainText()
        self.assertIn("hello world", encoded.replace("\u200b", "").replace("\u200c", ""))
        self.panel.input_edit.setPlainText(encoded)
        self.panel._on_decode()
        self.assertEqual(self.panel.output_edit.toPlainText(), "flag{zero_width}")

    def test_pigpen_ui(self):
        self.select("猪圈密码")
        separator = self.panel._param_edits["separator"]
        separator.setCurrentIndex(separator.findData("/"))
        self.panel.input_edit.setPlainText("flag{welcome come to ctf}")
        self.panel._on_encode()
        self.assertEqual(
            self.panel.output_edit.toPlainText(),
            "⊏/└•/┘/┐/∨•/□/└•/└/⊏•/⊐•/□/└/⊏•/⊐•/□/>/⊏•/└/>/⊏",
        )

        separator.setCurrentIndex(separator.findData(" "))
        self.panel.input_edit.setPlainText("HELLO")
        self.panel._on_encode()
        self.assertEqual(self.panel.output_edit.toPlainText(), "⊓ □ └• └• ⊏•")

    def test_affine_ui(self):
        self.select("仿射密码")
        a_widget = self.panel._param_edits["a"]
        b_widget = self.panel._param_edits["b"]
        remove_widget = self.panel._param_edits["remove_punctuation"]
        self.assertIsInstance(a_widget, QComboBox)
        self.assertIsInstance(b_widget, QComboBox)
        self.assertIsInstance(remove_widget, QCheckBox)
        a_widget.setCurrentIndex(a_widget.findData("5"))
        b_widget.setCurrentIndex(b_widget.findData("8"))
        self.panel.input_edit.setPlainText("flag{welcome come to ctf}")
        self.panel._on_encode()
        self.assertEqual(self.panel.output_edit.toPlainText(),
                         "hlim{oclsaqc saqc za szh}")
        self.panel.input_edit.setPlainText("hlim{oclsaqc saqc za szh}")
        self.panel._on_decode()
        self.assertEqual(self.panel.output_edit.toPlainText(),
                         "flag{welcome come to ctf}")

        remove_widget.setChecked(True)
        self.panel.input_edit.setPlainText("flag{welcome come to ctf}")
        self.panel._on_encode()
        self.assertEqual(self.panel.output_edit.toPlainText(),
                         "hlimoclsaqcsaqczaszh")

    def test_morse_ui_braces_and_lowercase(self):
        self.select("摩斯电码")
        self.panel.input_edit.setPlainText(
            "..-. .-.. .- --. ----.-- .-- . .-.. -.-. --- -- . / "
            "-.-. --- -- . / - --- / -.-. - ..-. -----.-"
        )
        self.panel._on_decode()
        self.assertEqual(self.panel.output_edit.toPlainText(), "flag{welcome come to ctf}")

    def test_rail_fence_dropdown(self):
        self.select("栅栏密码")
        widget = self.panel._param_edits["fence_type"]
        self.assertIsInstance(widget, QComboBox)
        widget.setCurrentIndex(widget.findData("标准"))
        self.panel._param_edits["rails"].setText("3")
        self.panel.input_edit.setPlainText("HELLOWORLD")
        self.panel._on_encode()
        self.assertEqual(self.panel.output_edit.toPlainText(), "HLODEORLWL")

    def test_hill_browser_mode_ui(self):
        self.select("Hill 密码")
        self.panel.key_edit.setText("2,5,9,5")
        self.panel.input_edit.setPlainText("flag{welcome come to ctf}")
        self.panel._on_encode()
        self.assertEqual(self.panel.output_edit.toPlainText(), "NWEESILNWKSYWZKEZBEHWZLOBF")

        self.panel.input_edit.setPlainText("NWEESILNWKSYWZKEZBEHWZLOBF")
        self.panel._on_decode()
        self.assertEqual(self.panel.output_edit.toPlainText(), "flag{welcome come to ctf}")

        # 模式2
        mode_widget = self.panel._param_edits["mode"]
        self.assertIsInstance(mode_widget, QComboBox)
        mode_widget.setCurrentIndex(mode_widget.findData("2"))
        self.panel.input_edit.setPlainText("flag{welcome come to ctf}")
        self.panel._on_encode()
        self.assertEqual(self.panel.output_edit.toPlainText(), "TJKRYVRACXYLCMQRFOKUCMRBHS")
        self.panel.input_edit.setPlainText("TJKRYVRACXYLCMQRFOKUCMRBHS")
        self.panel._on_decode()
        self.assertEqual(self.panel.output_edit.toPlainText(), "flag{welcome come to ctf}")


if __name__ == "__main__":
    unittest.main()
