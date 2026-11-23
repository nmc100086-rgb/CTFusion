"""v2.3 杂项工具测试：二维码、乱码、Base64/Hex、文件属性。"""

from __future__ import annotations

import base64
import io
import os
import shutil
import struct
import sys
import unittest
import uuid
import zipfile
import zlib
from contextlib import contextmanager
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core import datatools, fileprops, mojibake, qrcode  # noqa: E402

try:
    from PySide6.QtCore import QBuffer, QIODevice
    from PySide6.QtGui import QGuiApplication, QImage
    from PySide6.QtWidgets import QApplication

    from ui.main_window import MainWindow
except ImportError:  # pragma: no cover
    QApplication = None  # type: ignore[assignment]
    QImage = None  # type: ignore[assignment]
    QGuiApplication = None  # type: ignore[assignment]
    QBuffer = None  # type: ignore[assignment]
    QIODevice = None  # type: ignore[assignment]
    MainWindow = None  # type: ignore[assignment]


@contextmanager
def workspace_tempdir():
    """在工作区创建临时目录，避开沙箱对系统临时目录的 ACL 限制。"""
    base = ROOT / ".tmp"
    base.mkdir(parents=True, exist_ok=True)
    path = base / f"test-{uuid.uuid4().hex}"
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def qr_png(text: str) -> bytes:
    """用 zxing-cpp 生成二维码 PNG；依赖缺失时跳过调用方。"""
    import zxingcpp
    from PIL import Image

    barcode = zxingcpp.create_barcode(text, zxingcpp.BarcodeFormat.QRCode)
    image = barcode.to_image(scale=8)
    width, height = image.shape
    pil = Image.frombytes("L", (width, height), bytes(memoryview(image)))
    buffer = io.BytesIO()
    pil.save(buffer, "PNG")
    return buffer.getvalue()


def tiny_png() -> bytes:
    """生成 CRC 正确的 1×1 RGB PNG。"""
    def chunk(kind: bytes, body: bytes) -> bytes:
        return (struct.pack(">I", len(body)) + kind + body
                + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00"))
            + chunk(b"IEND", b""))


class MojibakeTests(unittest.TestCase):
    original = "你好，世界！flag{测试}"

    def test_utf8_as_latin1(self):
        garbled = self.original.encode("utf-8").decode("latin-1")
        self.assertTrue(mojibake.looks_garbled(garbled))
        candidates = mojibake.repair_candidates(garbled)
        self.assertEqual(candidates[0].text, self.original)
        self.assertIn("UTF-8", candidates[0].method)

    def test_gbk_as_latin1(self):
        garbled = self.original.encode("gbk").decode("latin-1")
        candidates = mojibake.repair_candidates(garbled)
        self.assertEqual(candidates[0].text, self.original)

    def test_utf8_as_gbk(self):
        garbled = self.original.encode("utf-8").decode("gb18030")
        self.assertTrue(mojibake.looks_garbled(garbled))
        candidates = mojibake.repair_candidates(garbled)
        self.assertEqual(candidates[0].text, self.original)

    def test_double_mojibake(self):
        garbled = (self.original.encode("utf-8").decode("latin-1")
                   .encode("utf-8").decode("latin-1"))
        candidates = mojibake.repair_candidates(garbled)
        self.assertEqual(candidates[0].text, self.original)

    def test_normal_text_has_no_repair(self):
        for text in ("Hello world, this is a test.", "flag{hello_world}",
                     self.original):
            self.assertFalse(mojibake.looks_garbled(text))
            self.assertEqual(mojibake.repair_candidates(text), [])

    def test_hex_bytes_candidates(self):
        candidates = mojibake.repair_bytes_candidates(self.original.encode("gbk"))
        self.assertEqual(candidates[0].text, self.original)

    def test_manual_conversion(self):
        result = mojibake.convert_text("ÄãºÃ£¬ÊÀ½ç", "Latin-1", "GB18030")
        self.assertEqual(result.text, "你好，世界")
        result = mojibake.convert_text(
            "c4e3bac3", "GB18030", "GB18030", input_is_hex=True)
        self.assertEqual(result.text, "你好")

    def test_manual_conversion_errors(self):
        with self.assertRaises(mojibake.MojibakeError):
            mojibake.convert_text("abc", "UTF-8", "GBK", input_is_hex=True)
        with self.assertRaises(mojibake.MojibakeError):
            mojibake.convert_text("abc", "ASCII", "UTF-8")


class DataToolTests(unittest.TestCase):
    def test_base64_png(self):
        payload = datatools.decode_payload(base64.b64encode(tiny_png()).decode())
        self.assertEqual(payload.kind, "PNG")
        self.assertTrue(payload.is_image)
        self.assertEqual(payload.extension, ".png")
        self.assertEqual(payload.data, tiny_png())

    def test_data_uri_png(self):
        encoded = "data:image/png;base64," + base64.b64encode(tiny_png()).decode()
        payload = datatools.decode_payload(encoded)
        self.assertEqual(payload.kind, "PNG")

    def test_hex_zip(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("flag.txt", "flag{hex_zip}")
        payload = datatools.decode_payload(buffer.getvalue().hex())
        self.assertEqual(payload.kind, "ZIP")
        self.assertTrue(payload.is_zip)
        self.assertEqual(payload.extension, ".zip")
        with zipfile.ZipFile(io.BytesIO(payload.data)) as archive:
            self.assertEqual(archive.read("flag.txt"), b"flag{hex_zip}")

    def test_hex_with_separators(self):
        payload = datatools.decode_payload("50 4B 03 04 00 00 00 00", "hex")
        self.assertEqual(payload.data[:4], b"PK\x03\x04")

    def test_auto_prefers_hex_for_pure_hex(self):
        self.assertEqual(datatools.decode_payload("deadbeef").method, "Hex")

    def test_invalid_inputs(self):
        with self.assertRaises(datatools.DataToolError):
            datatools.decode_payload("zzzz", "hex")
        with self.assertRaises(datatools.DataToolError):
            datatools.decode_payload("abc", "hex")
        with self.assertRaises(datatools.DataToolError):
            datatools.decode_payload("!!!!", "base64")
        with self.assertRaises(datatools.DataToolError):
            datatools.decode_payload("   ")

    def test_encode_roundtrip(self):
        data = tiny_png()
        for mode in ("base64", "hex"):
            encoded = datatools.encode_data(data, mode)
            payload = datatools.decode_payload(encoded, mode)
            self.assertEqual(payload.data, data)


@unittest.skipUnless(qrcode.available(), "需要 zxing-cpp 和 Pillow")
class QrCoreTests(unittest.TestCase):
    def test_scan_png(self):
        results = qrcode.scan_image_bytes(qr_png("flag{qr_core}"))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].text, "flag{qr_core}")
        self.assertEqual(results[0].raw, b"flag{qr_core}")
        self.assertIn("QR", results[0].format)

    def test_no_barcode(self):
        image = QImage(80, 80, QImage.Format_RGB32)
        image.fill(0xFFFFFFFF)
        buffer = QBuffer()
        buffer.open(QIODevice.WriteOnly)
        image.save(buffer, "PNG")
        self.assertEqual(qrcode.scan_image_bytes(bytes(buffer.data())), [])

    def test_self_test(self):
        ok, message = qrcode.self_test()
        self.assertTrue(ok, message)


class FilePropsTests(unittest.TestCase):
    def test_collect_and_text(self):
        with workspace_tempdir() as temp:
            path = temp / "样例.txt"
            path.write_text("flag{props}", encoding="utf-8")
            sections = fileprops.collect(path, compute_hashes=True)
            titles = [section.title for section in sections]
            self.assertIn("路径", titles)
            self.assertIn("时间", titles)
            self.assertIn("属性 / 权限", titles)
            self.assertIn("哈希", titles)
            text = fileprops.sections_to_text(sections)
            self.assertIn("样例.txt", text)
            self.assertIn("SHA256", text)
            # 路径必须是绝对路径，不能显示成 "." 目录。
            rows = dict(next(s for s in sections if s.title == "路径").rows)
            self.assertEqual(rows["所在目录"], str(temp))


@unittest.skipUnless(QApplication is not None, "需要安装 PySide6")
class MiscUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.window = MainWindow()

    def tearDown(self):
        self.window.close()

    def test_main_window_has_misc_and_properties(self):
        labels = [self.window.tabs.tabText(i)
                  for i in range(self.window.tabs.count())]
        self.assertIn("实用工具", labels)
        file_labels = [self.window.file_panel.tabs.tabText(i)
                       for i in range(self.window.file_panel.tabs.count())]
        self.assertIn("文件属性", file_labels)
        self.assertEqual(self.window.misc_panel.tabs.count(), 3)

    @unittest.skipUnless(qrcode.available(), "需要 zxing-cpp 和 Pillow")
    def test_qr_tab_load_and_copy(self):
        with workspace_tempdir() as temp:
            path = temp / "qr.png"
            path.write_bytes(qr_png("flag{qr_ui}"))
            tab = self.window.misc_panel.qr_tab
            self.assertTrue(tab.load_file(str(path)))
            self.assertEqual(tab.table.rowCount(), 1)
            tab._copy_selected()
            self.assertEqual(QGuiApplication.clipboard().text(), "flag{qr_ui}")
            tab._copy_raw_hex()
            self.assertEqual(
                QGuiApplication.clipboard().text(),
                b"flag{qr_ui}".hex(" ").upper())

    def test_qr_tab_empty_hint(self):
        tab = self.window.misc_panel.qr_tab
        tab._scan()
        self.assertIn("请先打开图片", tab.status.text())

    @unittest.skipUnless(qrcode.available(), "需要 zxing-cpp 和 Pillow")
    def test_image_panel_qr_button_routes_to_misc(self):
        with workspace_tempdir() as temp:
            path = temp / "qr_from_image.png"
            path.write_bytes(qr_png("flag{image_to_qr}"))
            panel = self.window.image_panel
            self.assertTrue(panel.load_file(str(path)))
            self.assertTrue(panel.btn_qr.isEnabled())
            panel.btn_qr.click()
            self.assertIs(self.window.tabs.currentWidget(), self.window.misc_panel)
            self.assertIs(
                self.window.misc_panel.tabs.currentWidget(),
                self.window.misc_panel.qr_tab)
            tab = self.window.misc_panel.qr_tab
            self.assertEqual(tab.table.rowCount(), 1)
            tab._copy_selected()
            self.assertEqual(
                QGuiApplication.clipboard().text(), "flag{image_to_qr}")

    def test_mojibake_tab_uses_raw_text(self):
        tab = self.window.misc_panel.mojibake_tab
        # 包含 U+00A0，QPlainTextEdit.toPlainText() 会把它变成空格。
        garbled = "你好，世界！flag{测试}".encode("utf-8").decode("latin-1")
        tab.input_edit.setPlainText(garbled)
        self.assertIn("\u00a0", tab._input_text())
        tab._auto_analyze()
        self.assertGreaterEqual(tab.table.rowCount(), 1)
        self.assertEqual(tab.output.toPlainText(), "你好，世界！flag{测试}")
        tab._copy()
        self.assertEqual(
            QGuiApplication.clipboard().text(), "你好，世界！flag{测试}")

    def test_mojibake_tab_no_result_hint(self):
        tab = self.window.misc_panel.mojibake_tab
        tab.input_edit.setPlainText("Hello world, nothing garbled here.")
        tab._auto_analyze()
        self.assertEqual(tab.table.rowCount(), 0)
        self.assertIn("未检测到", tab.status.text())

    def test_data_tab_preview_and_save_enabled(self):
        tab = self.window.misc_panel.data_tab
        tab.decode_input.setPlainText(base64.b64encode(tiny_png()).decode())
        tab._decode()
        self.assertIsNotNone(tab._decoded)
        self.assertEqual(tab._decoded.kind, "PNG")
        self.assertTrue(tab.btn_save.isEnabled())
        self.assertTrue(tab.btn_save_open.isEnabled())
        self.assertIn("PNG", tab.decode_status.text())

    def test_data_tab_invalid_input(self):
        tab = self.window.misc_panel.data_tab
        tab.decode_input.setPlainText("not base64 !!!")
        tab._decode()
        self.assertIsNone(tab._decoded)
        self.assertFalse(tab.btn_save.isEnabled())

    def test_file_properties_tab(self):
        self.window.open_file(str(ROOT / "README.md"))
        panel = self.window.file_panel
        self.assertGreater(panel.props_tree.topLevelItemCount(), 0)
        titles = [panel.props_tree.topLevelItem(i).text(0)
                  for i in range(panel.props_tree.topLevelItemCount())]
        self.assertIn("路径", titles)
        self.assertIn("哈希", titles)
        panel._copy_properties()
        self.assertIn("README.md", QGuiApplication.clipboard().text())

    def test_image_tools_no_duplicate_combine_buttons(self):
        panel = self.window.image_panel
        self.assertFalse(hasattr(panel, "btn_xor"))
        self.assertFalse(hasattr(panel, "btn_diff"))
        self.assertTrue(hasattr(panel.image_analysis, "combine_op"))


if __name__ == "__main__":
    unittest.main()
