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

from core import fileparse, lsb  # noqa: E402
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


def exif_jpg_bytes() -> bytes:
    """构造带一个 EXIF 制造商标签的最小 JPEG。"""
    tiff = b"II\x2a\x00" + struct.pack("<I", 8)
    entry = struct.pack("<HHI", 0x010F, 2, 6) + struct.pack("<I", 26)
    ifd = struct.pack("<H", 1) + entry + struct.pack("<I", 0)
    payload = b"Exif\x00\x00" + tiff + ifd + b"Canon\x00"
    return (b"\xff\xd8" + b"\xff\xe1" + struct.pack(">H", len(payload) + 2)
            + payload + b"\xff\xd9")


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

    def test_header_check(self):
        result = identify(png_bytes(), "a.png")
        self.assertIsNotNone(result.header)
        self.assertTrue(result.header.matched)
        self.assertEqual(result.header.offset, 0)
        self.assertEqual(result.header.name, "PNG")
        self.assertEqual(result.header.expected_hex, "89 50 4E 47 0D 0A 1A 0A")
        unknown = identify(b"\x01\x02\x03\x04", "a.bin")
        self.assertFalse(unknown.header.matched)
        self.assertEqual(unknown.header.expected, b"")


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


class ImageAnalysisTests(unittest.TestCase):
    def test_png_info_and_crc_repair(self):
        data = png_bytes(bad_crc=True)
        info = fileparse.png_info(data)
        self.assertIsNotNone(info)
        self.assertEqual((info.width, info.height), (1, 1))
        self.assertEqual(info.color_type, 2)
        self.assertEqual(len(info.crc_errors), 1)
        fixed = fileparse.repair_png_crc(data)
        self.assertEqual(fileparse.png_info(fixed).crc_errors, [])
        self.assertTrue(fixed.endswith(png_bytes()[-12:]))

    def test_png_dimension_repair(self):
        fixed = fileparse.repair_png_dimensions(png_bytes(), 5, 7)
        info = fileparse.png_info(fixed)
        self.assertEqual((info.width, info.height), (5, 7))
        self.assertEqual(info.crc_errors, [])

    def test_png_actual_size(self):
        self.assertEqual(fileparse.png_actual_size(png_bytes()), (1, 1))

    def test_image_info(self):
        rows = dict(fileparse.image_info("PNG", png_bytes()))
        self.assertEqual(rows["尺寸"], "1 x 1")
        self.assertEqual(rows["CRC 校验"], "全部通过")
        gif_rows = dict(fileparse.image_info("GIF", gif_bytes()))
        self.assertEqual(gif_rows["帧数"], "0")

    def test_exif(self):
        rows = dict(fileparse.parse_exif(exif_jpg_bytes()))
        self.assertEqual(rows.get("制造商"), "Canon")
        self.assertEqual(fileparse.parse_exif(png_bytes()), [])

    def test_gif_frame_offsets(self):
        self.assertEqual(fileparse.gif_frame_offsets(gif_bytes()), [])

    def test_lsb_bit_plane_and_extract(self):
        on = bytes([1, 0, 0, 255])
        off = bytes([0, 0, 0, 255])
        pixels = on * 4 + off * 4
        self.assertEqual(list(lsb.bit_plane(pixels, 4, 0, 0)), [255, 255, 255, 255, 0, 0, 0, 0])
        self.assertEqual(lsb.extract_bytes(pixels, 4, 0, 0), b"\xF0")


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
    from PySide6.QtCore import QBuffer, QIODevice, Qt
    from PySide6.QtGui import QImage
    from PySide6.QtWidgets import QApplication

    from ui.main_window import MainWindow
except ImportError:  # pragma: no cover
    QApplication = None  # type: ignore[assignment]
    MainWindow = None  # type: ignore[assignment]


@unittest.skipUnless(QApplication is not None, "需要安装 PySide6")
class FilePanelSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_load_png_shows_structure_and_trailing(self):
        window = MainWindow()
        try:
            panel = window.file_panel
            data = png_bytes(trailing=b"PK\x03\x04hidden")
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "test.png")
                with open(path, "wb") as f:
                    f.write(data)
                panel.load_file(path)

            self.assertEqual(len(panel.hex_viewer.model.data_bytes), len(data))
            self.assertIn("尾随数据", panel.overview.toPlainText())
            self.assertIn("CRC", panel.overview.toPlainText())
            self.assertIn("图像信息", panel.overview.toPlainText())
            self.assertGreaterEqual(panel.structure.topLevelItemCount(), 3)
            self.assertGreater(panel.string_table.rowCount(), 0)

            header = dict(
                (panel.header_table.item(r, 0).text(), panel.header_table.item(r, 1).text())
                for r in range(panel.header_table.rowCount())
            )
            self.assertEqual(header["期望 magic"], "89 50 4E 47 0D 0A 1A 0A")
            self.assertIn("ZIP", header["尾随数据"])

            panel.hex_viewer.goto_offset(len(data) - 1)
            self.assertTrue(panel.hex_viewer.inspector.rowCount() > 0)
        finally:
            window.close()

    def test_load_unknown_format(self):
        window = MainWindow()
        try:
            panel = window.file_panel
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "x.dat")
                with open(path, "wb") as f:
                    f.write(b"\x00\x01\x02\x03" * 10)
                panel.load_file(path)
            self.assertIn("暂未支持结构解析", panel.structure.topLevelItem(0).text(0))
        finally:
            window.close()

    def test_hex_edit_undo_redo_save(self):
        window = MainWindow()
        try:
            panel = window.file_panel
            data = png_bytes()
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "edit.png")
                with open(path, "wb") as f:
                    f.write(data)
                panel.load_file(path)
                viewer = panel.hex_viewer
                self.assertFalse(viewer.is_modified)
                self.assertTrue(viewer.apply_edit(0, b"\x90"))
                self.assertEqual(viewer.model.data_bytes[:1], b"\x90")
                self.assertTrue(viewer.is_modified)
                self.assertIn("已修改", panel.file_label.text())
                viewer.undo()
                self.assertEqual(viewer.model.data_bytes, data)
                viewer.redo()
                self.assertEqual(viewer.model.data_bytes[:1], b"\x90")
                saved = os.path.join(tmp, "saved.png")
                self.assertTrue(viewer.save_to(saved))
                with open(saved, "rb") as f:
                    self.assertEqual(f.read()[:1], b"\x90")
                self.assertFalse(viewer.is_modified)
        finally:
            window.close()


@unittest.skipUnless(QApplication is not None, "需要安装 PySide6")
class ImagePanelSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def _png_bytes(self) -> bytes:
        image = QImage(4, 4, QImage.Format_RGB32)
        image.fill(Qt.black)
        buffer = QBuffer()
        buffer.open(QIODevice.WriteOnly)
        image.save(buffer, "PNG")
        return bytes(buffer.data())

    def test_load_png_and_lsb(self):
        window = MainWindow()
        try:
            panel = window.image_panel
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "img.png")
                with open(path, "wb") as f:
                    f.write(self._png_bytes())
                panel.load_file(path)
            self.assertEqual(panel._kind, "PNG")
            self.assertGreaterEqual(panel.info_table.rowCount(), 5)
            self.assertEqual(panel.crc_table.rowCount(), 0)
            self.assertIn("2 字节", panel.lsb_capacity.text())
            panel._on_bitplane()
            self.assertFalse(panel.lsb_preview.pixmap().isNull())
            panel._on_extract()
            self.assertIn("通道 R", panel.lsb_output.toPlainText())
        finally:
            window.close()

    def test_png_crc_error_listed(self):
        window = MainWindow()
        try:
            panel = window.image_panel
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "bad.png")
                with open(path, "wb") as f:
                    f.write(png_bytes(bad_crc=True))
                panel.load_file(path)
            self.assertEqual(panel.crc_table.rowCount(), 1)
            self.assertIn("CRC 错误", panel.repair_log.toPlainText())
        finally:
            window.close()


if __name__ == "__main__":
    unittest.main()
