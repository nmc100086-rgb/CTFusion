"""文件分析模块的单元测试 + 页签离屏冒烟测试。"""

from __future__ import annotations

import io
import os
import struct
import sys
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core import fileparse  # noqa: E402
from core.analysis import digests, entropy, interpret_at, strings  # noqa: E402
from core.filetype import identify, identify_file  # noqa: E402


def png_bytes(trailing: bytes = b"", bad_crc: bool = False) -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"

    def chunk(ctype: bytes, body: bytes, corrupt: bool = False) -> bytes:
        crc = zlib.crc32(ctype + body) & 0xFFFFFFFF
        if corrupt:
            crc ^= 0xFFFF
        return struct.pack(">I", len(body)) + ctype + body + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    return (sig + chunk(b"IHDR", ihdr, bad_crc)
            + chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00"))
            + chunk(b"IEND", b"") + trailing)


def jpg_bytes(trailing: bytes = b"") -> bytes:
    app0 = struct.pack(">H", 16) + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    sos = struct.pack(">H", 12) + bytes([3, 1, 0, 2, 0x11, 3, 0x11, 0, 0x3F, 0])
    return b"\xff\xd8" + b"\xff\xe0" + app0 + b"\xff\xda" + sos + b"\x12\x34" + b"\xff\xd9" + trailing


def gif_bytes(trailing: bytes = b"") -> bytes:
    header = b"GIF89a"
    lsd = struct.pack("<HHBBB", 2, 2, 0x00, 0, 0)
    return header + lsd + b"\x3b" + trailing


def bmp_bytes() -> bytes:
    width, height = 2, 2
    pixel = b"\x00\x00\xff\xff" * 4
    size = 54 + len(pixel)
    header = (b"BM" + struct.pack("<IHHI", size, 0, 0, 54)
              + struct.pack("<iiiHHIIiiII", 40, width, height, 1, 24, 0,
                            len(pixel), 2835, 2835, 0, 0))
    return header + pixel


def zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("flag.txt", "hello misc")
    return buf.getvalue()


class FileTypeTests(unittest.TestCase):
    def test_png_identify_ok(self):
        result = identify(png_bytes(), "a.png")
        self.assertEqual(result.real_name, "PNG")
        self.assertTrue(result.ext_ok)

    def test_fake_extension_detected(self):
        result = identify(png_bytes(), "a.jpg")
        self.assertEqual(result.real_name, "PNG")
        self.assertFalse(result.ext_ok)
        self.assertTrue(any("伪造" in n for n in result.notes))

    def test_png_trailing_zip(self):
        data = png_bytes(trailing=b"PK\x03\x04rest")
        result = identify(data, "a.png")
        self.assertIsNotNone(result.trailing)
        self.assertEqual(result.trailing.offset, len(png_bytes()))
        self.assertIn("ZIP", result.trailing.hint)

    def test_text_and_unknown(self):
        self.assertEqual(identify(b"hello world\n" * 10, "a.txt").real_name, "纯文本")
        self.assertEqual(identify(b"\x01\x02\x03\x04\x05", "a.bin").real_name, "未知二进制")

    def test_other_formats(self):
        self.assertEqual(identify(jpg_bytes(), "a.jpg").real_name, "JPEG")
        self.assertEqual(identify(gif_bytes(), "a.gif").real_name, "GIF")
        self.assertEqual(identify(bmp_bytes(), "a.bmp").real_name, "BMP")
        self.assertEqual(identify(zip_bytes(), "a.zip").real_name, "ZIP")
        self.assertEqual(identify(b"%PDF-1.7\n", "a.pdf").real_name, "PDF")
        self.assertEqual(identify(b"\x7fELF\x02\x01", "a.elf").real_name, "ELF")
        self.assertEqual(identify(b"7z\xbc\xaf\x27\x1cxx", "a.7z").real_name, "7Z")
        self.assertEqual(identify(b"RAR!\x1a\x07\x00xx", "a.rar").real_name, "RAR")


class FileParseTests(unittest.TestCase):
    def test_png_chunks_and_crc(self):
        nodes, end = fileparse.parse_png(png_bytes())
        titles = [n.title for n in nodes]
        self.assertIn("IHDR", titles)
        self.assertIn("IEND", titles)
        self.assertTrue(any("CRC 正确" in n.detail for n in nodes if n.title == "IHDR"))
        self.assertEqual(end, len(png_bytes()))

    def test_png_bad_crc(self):
        nodes, _ = fileparse.parse_png(png_bytes(bad_crc=True))
        ihdr = next(n for n in nodes if n.title == "IHDR")
        self.assertIn("CRC 错误", ihdr.detail)
        self.assertIn("1x1", ihdr.detail)

    def test_jpg_segments(self):
        nodes, end = fileparse.parse_jpg(jpg_bytes())
        titles = [n.title for n in nodes]
        self.assertTrue(any("APP0" in t for t in titles))
        self.assertTrue(any("SOS" in t for t in titles))
        self.assertIn("EOI 文件尾", titles)
        self.assertEqual(end, len(jpg_bytes()))

    def test_gif_and_bmp(self):
        gif_nodes, gif_end = fileparse.parse_gif(gif_bytes())
        self.assertTrue(any("逻辑屏幕" in n.title for n in gif_nodes))
        self.assertEqual(gif_end, len(gif_bytes()))
        bmp_nodes, bmp_end = fileparse.parse_bmp(bmp_bytes())
        self.assertTrue(any("BITMAPFILEHEADER" in n.title for n in bmp_nodes))
        self.assertEqual(bmp_end, len(bmp_bytes()))

    def test_zip_entries(self):
        nodes, end = fileparse.parse_zip(zip_bytes())
        titles = [n.title for n in nodes]
        self.assertTrue(any("flag.txt" in t for t in titles))
        self.assertTrue(any("EOCD" in t for t in titles))
        self.assertEqual(end, len(zip_bytes()))


class AnalysisTests(unittest.TestCase):
    def test_entropy_bounds(self):
        self.assertAlmostEqual(entropy(b"\x00" * 100), 0.0, places=6)
        self.assertGreater(entropy(bytes(range(256)) * 4), 7.9)

    def test_digests(self):
        self.assertEqual(digests(b"abc")["MD5"], "900150983cd24fb0d6963f7d28e17f72")

    def test_strings(self):
        found = strings(b"\x00\x00flag{abc}\x00\x00hello", min_len=4)
        texts = [t for _, t in found]
        self.assertIn("flag{abc}", texts)
        self.assertIn("hello", texts)
        filtered = strings(b"\x00flag{abc}\x00hello", pattern="flag")
        self.assertEqual([t for _, t in filtered], ["flag{abc}"])

    def test_interpret_at(self):
        rows = dict(interpret_at(b"\x01\x00\x00\x00", 0))
        self.assertEqual(rows["字节"], "0x01 (1)")
        self.assertEqual(rows["uint32 LE"], "1")


try:
    from PySide6.QtWidgets import QApplication

    from ui.main_window import MainWindow
except ImportError:  # pragma: no cover
    QApplication = None  # type: ignore[assignment]
    MainWindow = None  # type: ignore[assignment]


@unittest.skipUnless(QApplication is not None, "需要安装 PySide6")
class StegoPanelSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_load_png_shows_structure_and_trailing(self):
        window = MainWindow()
        try:
            panel = window.stego_panel
            data = png_bytes(trailing=b"PK\x03\x04hidden")
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "test.png")
                with open(path, "wb") as f:
                    f.write(data)
                panel.load_file(path)

            self.assertEqual(len(panel.hex_viewer.model.data_bytes), len(data))
            self.assertIn("尾随数据", panel.overview.toPlainText())
            self.assertIn("CRC", panel.overview.toPlainText())
            self.assertGreaterEqual(panel.structure.topLevelItemCount(), 3)
            self.assertGreater(panel.string_table.rowCount(), 0)

            panel.hex_viewer.goto_offset(len(data) - 1)
            self.assertTrue(panel.hex_viewer.inspector.rowCount() > 0)
        finally:
            window.close()

    def test_load_unknown_format(self):
        window = MainWindow()
        try:
            panel = window.stego_panel
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "x.dat")
                with open(path, "wb") as f:
                    f.write(b"\x00\x01\x02\x03" * 10)
                panel.load_file(path)
            self.assertIn("暂未支持结构解析", panel.structure.topLevelItem(0).text(0))
        finally:
            window.close()


if __name__ == "__main__":
    unittest.main()
