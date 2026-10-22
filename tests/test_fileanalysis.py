"""文件分析模块的单元测试 + 页签离屏冒烟测试。"""

from __future__ import annotations

import base64
import io
import os
import struct
import sys
import tempfile
import unittest
import wave
import zipfile
import zlib
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core import audio, fileparse, lsb, stegsolve, zipcrack  # noqa: E402
from core.analysis import digests, entropy, interpret_at, strings  # noqa: E402
from core.detect import detect_encodings  # noqa: E402
from core.filetype import identify  # noqa: E402


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


def png_text_bytes() -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"

    def chunk(ctype: bytes, body: bytes) -> bytes:
        crc = zlib.crc32(ctype + body) & 0xFFFFFFFF
        return struct.pack(">I", len(body)) + ctype + body + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    text = b"Comment\x00flag{png_text}"
    return (sig + chunk(b"IHDR", ihdr) + chunk(b"tEXt", text)
            + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
            + chunk(b"IEND", b""))


def wav_lsb_bytes() -> bytes:
    message = b"flag{wav_lsb}"
    bits = [(byte >> shift) & 1 for byte in message for shift in range(7, -1, -1)]
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(1)
        wav.setframerate(8000)
        wav.writeframes(bytes(bits))
    return buf.getvalue()


def png_exif_bytes() -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"

    def chunk(ctype: bytes, body: bytes) -> bytes:
        crc = zlib.crc32(ctype + body) & 0xFFFFFFFF
        return struct.pack(">I", len(body)) + ctype + body + struct.pack(">I", crc)

    tiff = b"II\x2a\x00" + struct.pack("<I", 8)
    entry = struct.pack("<HHI", 0x010F, 2, 6) + struct.pack("<I", 26)
    ifd = struct.pack("<H", 1) + entry + struct.pack("<I", 0)
    payload = tiff + ifd + b"Canon\x00"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    return (sig + chunk(b"IHDR", ihdr) + chunk(b"eXIf", payload)
            + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
            + chunk(b"IEND", b""))


def png_sized(width: int, height: int) -> bytes:
    """构造一个 RGB PNG,用于测试 IHDR 宽高被篡改后的推断。"""
    sig = b"\x89PNG\r\n\x1a\n"

    def chunk(ctype: bytes, body: bytes) -> bytes:
        crc = zlib.crc32(ctype + body) & 0xFFFFFFFF
        return struct.pack(">I", len(body)) + ctype + body + struct.pack(">I", crc)

    raw = b"".join(
        b"\x00" + b"".join(bytes([x % 256, y % 256, 0]) for x in range(width))
        for y in range(height)
    )
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw))
            + chunk(b"IEND", b""))


# 8x8 progressive JPEG(由 Pillow 生成后固化,避免测试依赖 Pillow)
PROGRESSIVE_JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAYEBQYFBAYGBQYHBwYIChAKCgkJChQODwwQFxQYGBcU"
    "FhYaHSUfGhsjHBYWICwgIyYnKSopGR8tMC0oMCUoKSj/2wBDAQcHBwoIChMKChMoGhYaKCgoKCgo"
    "KCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCj/wgARCAAIAAgDASIA"
    "AhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAb/xAAUAQEAAAAAAAAAAAAAAAAAAAAB/9oADAMBAAIQ"
    "AxAAAAGaA//EABYQAAMAAAAAAAAAAAAAAAAAAAADBP/aAAgBAQABBQJMp//EABcRAAMBAAAAAAAA"
    "AAAAAAAAAAACBBP/2gAIAQMBAT8BjofM/8QAFxEAAwEAAAAAAAAAAAAAAAAAAAIDEf/aAAgBAgEB"
    "PwGl30//xAAVEAEBAAAAAAAAAAAAAAAAAAAAMf/aAAgBAQAGPwKP/8QAFRABAQAAAAAAAAAAAAAA"
    "AAAAADH/2gAIAQEAAT8hmf/aAAwDAQACAAMAAAAQ/wD/xAAWEQADAAAAAAAAAAAAAAAAAAAAESH/"
    "2gAIAQMBAT8QT0//xAAVEQEBAAAAAAAAAAAAAAAAAAAAQf/aAAgBAgEBPxCi/8QAFRABAQAAAAAA"
    "AAAAAAAAAAAAAPH/2gAIAQEAAT8QmP/Z"
)

# 3 帧 2x2 GIF(由 Pillow 生成后固化)
THREE_FRAME_GIF = base64.b64decode(
    "R0lGODlhAgACAIAAAAAAAAAAACH/C05FVFNDQVBFMi4wAwEAAAAh+QQABQAAACwAAAAAAgACAAAI"
    "BwABBBAwICAAIfkEAAUAAAAsAAAAAAIAAgAACAcAAwgYACAgACH5BAAFAAAALAAAAAACAAIAAAgH"
    "AAUMABAgIAA7"
)


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

    def test_weak_magic_is_not_bmp_or_pe(self):
        self.assertEqual(identify(b"BMW is a car\r\n" * 10, "note.txt").real_name, "纯文本")
        self.assertEqual(identify(b"MZ is just text\r\n" * 10, "note.txt").real_name, "纯文本")

    def test_unicode_text_detection(self):
        cn = "你好,世界!这是一段中文提示。".encode("utf-8")
        self.assertEqual(identify(cn, "note.txt").real_name, "纯文本")
        self.assertEqual(identify(cn, "note.txt").text_encoding, "UTF-8")
        utf16 = "hello world".encode("utf-16")
        self.assertEqual(identify(utf16, "note.txt").real_name, "纯文本")
        self.assertEqual(identify(utf16, "note.txt").text_encoding, "UTF-16")

    def test_prepended_png_is_detected(self):
        data = b"GARBAGE" + png_bytes()
        result = identify(data, "note.txt")
        self.assertEqual(result.real_name, "PNG")
        self.assertEqual(result.prefix, 7)
        self.assertTrue(result.header.matched)
        self.assertEqual(result.header.offset, 7)


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

    def test_progressive_jpeg_has_no_false_trailing(self):
        nodes, end = fileparse.parse_jpg(PROGRESSIVE_JPEG)
        self.assertEqual(end, len(PROGRESSIVE_JPEG))
        self.assertEqual(nodes[-1].title, "EOI 文件尾")
        self.assertIsNone(identify(PROGRESSIVE_JPEG, "a.jpg").trailing)

    def test_gif_multiframe_parse(self):
        nodes, end = fileparse.parse_gif(THREE_FRAME_GIF)
        frames = [n for n in nodes if n.title.startswith("图像帧")]
        self.assertEqual(len(frames), 3)
        self.assertEqual(end, len(THREE_FRAME_GIF))
        self.assertEqual(len(fileparse.gif_frame_offsets(THREE_FRAME_GIF)), 3)

    def test_zip_comment_with_fake_eocd(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.txt", "hello")
            zf.comment = b"PK\x05\x06 fake eocd in comment"
        data = buf.getvalue()
        nodes, end = fileparse.parse_zip(data)
        self.assertEqual(end, len(data))
        self.assertTrue(any(n.title == "压缩包注释" for n in nodes))

    def test_zip_pseudo_encryption_detection_and_repair(self):
        data = bytearray(zip_bytes())
        data[6] |= 1  # 只改本地头的加密位
        info = zipcrack.inspect(bytes(data))
        self.assertTrue(info.entries[0].pseudo)
        fixed, count = zipcrack.repair_pseudo_encryption(bytes(data))
        self.assertEqual(count, 1)
        self.assertFalse(fixed[6] & 1)
        with zipfile.ZipFile(io.BytesIO(fixed)) as zf:
            self.assertEqual(zf.read("flag.txt"), b"hello misc")


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

    def test_png_actual_size_when_width_tampered(self):
        data = bytearray(png_sized(100, 10))
        data[16:20] = struct.pack(">I", 10)
        crc = zlib.crc32(bytes(data[12:29])) & 0xFFFFFFFF
        data[29:33] = struct.pack(">I", crc)
        self.assertEqual(fileparse.png_actual_size(bytes(data)), (100, 10))
        data = bytearray(png_sized(100, 10))
        data[20:24] = struct.pack(">I", 20)
        crc = zlib.crc32(bytes(data[12:29])) & 0xFFFFFFFF
        data[29:33] = struct.pack(">I", crc)
        self.assertEqual(fileparse.png_actual_size(bytes(data)), (100, 10))

    def test_png_text_chunks(self):
        rows = fileparse.png_text_chunks(png_text_bytes())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].keyword, "Comment")
        self.assertIn("flag{png_text}", rows[0].text)

    def test_png_exif(self):
        rows = dict(fileparse.parse_exif(png_exif_bytes()))
        self.assertEqual(rows.get("制造商"), "Canon")

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

    def test_lsb_bit_order_and_multichannel(self):
        bits = bytes([0, 1, 0, 0, 0, 0, 0, 1])
        self.assertEqual(lsb.extract_bytes(bits, 1, 0, 0, bit_order="msb"), b"\x41")
        self.assertEqual(lsb.extract_bytes(bits, 1, 0, 0, bit_order="lsb"), b"\x82")
        # 2 像素 x 2 通道 = 4 bit; 再补 4 bit 才成字节
        pixels = bytes([1, 0, 0, 1, 1, 1, 0, 0])
        self.assertEqual(
            lsb.extract_bytes(pixels, 2, 0, 0, channels_sel=(0, 1)), b"\x9C")

    def test_stegsolve_multibit_extract(self):
        bits = [(byte >> shift) & 1 for byte in b"A" for shift in range(7, -1, -1)]
        pixels = b"".join(bytes([bit, 0, 0, 255]) for bit in bits)
        self.assertEqual(
            stegsolve.extract_selected(pixels, 4, {0: {0}}, (0,)), b"A")
        self.assertEqual(
            stegsolve.extract_selected(pixels, 4, {0: {0}}, (0,),
                                       bit_order="lsb"), b"\x82")

    def test_lsb_row_scan_finds_flag_in_single_channel(self):
        message = b"flag{row_scan}"
        bits = [(byte >> shift) & 1 for byte in message for shift in range(7, -1, -1)]
        pixels = b"".join(bytes([bit, 0, 0, 255]) for bit in bits)
        results = lsb.scan_orders(pixels, 4, ("R", "G", "B", "A"),
                                  max_bytes=len(message))
        single = next(item for item in results if item.label == "R")
        self.assertEqual(single.text, message.decode())
        self.assertTrue(single.has_flag)


class AudioTests(unittest.TestCase):
    def test_wav_info_and_lsb(self):
        data = wav_lsb_bytes()
        info = audio.read_info(data)
        self.assertIsNotNone(info)
        self.assertEqual(info.channels, 1)
        self.assertEqual(info.sample_width, 1)
        extracted = audio.extract_lsb(data, bit=0)
        self.assertEqual(extracted, b"flag{wav_lsb}")


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
        limited = strings(b"\x00aaaa\x00bbbb\x00cccc", min_len=4, limit=1)
        self.assertEqual([t for _, t in limited], ["aaaa"])

    def test_detect_encodings(self):
        payload = (
            b"http://example.com/a "
            + base64.b64encode(b"flag{base64_hit}")
            + b" "
            + b"flag{hex_hit}".hex().encode()
        )
        found = detect_encodings(payload)
        kinds = {item.kind for item in found}
        self.assertIn("URL", kinds)
        self.assertIn("Base64", kinds)
        self.assertIn("Hex", kinds)
        decoded = " ".join(item.decoded for item in found)
        self.assertIn("flag{base64_hit}", decoded)
        self.assertIn("flag{hex_hit}", decoded)

    def test_interpret_at(self):
        rows = dict(interpret_at(b"\x01\x00\x00\x00", 0))
        self.assertEqual(rows["字节"], "0x01 (1)")
        self.assertEqual(rows["uint32 LE"], "1")


try:
    from PySide6.QtCore import QBuffer, QIODevice, Qt
    from PySide6.QtGui import QColor, QImage
    from PySide6.QtTest import QTest
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

    def test_read_only_file_marks_viewer(self):
        window = MainWindow()
        try:
            panel = window.file_panel
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "ro.bin")
                with open(path, "wb") as f:
                    f.write(b"read only")
                os.chmod(path, 0o444)
                panel.load_file(path)
                self.assertTrue(panel._read_only)
                self.assertTrue(panel.hex_viewer._read_only)
                self.assertIn("只读", panel.file_label.text())
                os.chmod(path, 0o666)
        finally:
            window.close()

    def test_hex_search_ascii_case_insensitive_and_highlight(self):
        window = MainWindow()
        try:
            viewer = window.file_panel.hex_viewer
            viewer.set_data(b"Hello hello HELLO\x00FF")
            viewer.search_mode.setCurrentIndex(viewer.search_mode.findData("ascii"))
            viewer.search_edit.setText("hello")
            viewer._on_search()
            self.assertEqual(len(viewer._matches), 3)
            self.assertIn(0, viewer.model._highlight_bytes)

            # 不点“查找全部”,直接点下一个也应自动搜索。
            viewer.search_edit.setText("HELLO")
            viewer._step(1)
            self.assertEqual(len(viewer._matches), 3)
            self.assertEqual(viewer._match_pos, 0)
            viewer._step(1)
            self.assertEqual(viewer._match_pos, 1)

            # 第二行的命中必须是行内位置,否则 delegate 会跳过整行。
            viewer.set_data(b"hello" + b"X" * 27 + b"hello")
            viewer.search_edit.setText("hello")
            viewer.search_mode.setCurrentIndex(viewer.search_mode.findData("ascii"))
            viewer._on_search()
            self.assertEqual(viewer.model.match_bytes_for_row(2), {0, 1, 2, 3, 4})

            viewer.set_data(b"Hello hello HELLO\x00FF")
            viewer.search_mode.setCurrentIndex(viewer.search_mode.findData("hex"))
            viewer.search_edit.setText("48 65")
            viewer._step(1)
            self.assertEqual(len(viewer._matches), 1)
            self.assertEqual(viewer._matches[0], 0)
        finally:
            window.close()

    def test_hex_edit_byte_via_table_path(self):
        window = MainWindow()
        try:
            viewer = window.file_panel.hex_viewer
            viewer.set_data(b"\x11\x22\x33")
            cell = viewer.table.visualRect(viewer.model.index(0, 1)).center()
            with patch.object(viewer, "_edit_byte") as edit:
                QTest.mouseDClick(viewer.table.viewport(), Qt.LeftButton, pos=cell)
                edit.assert_called_once()
            with patch("ui.hex_viewer.QInputDialog.getText",
                       return_value=("AA", True)):
                viewer._edit_byte(1)
            self.assertEqual(viewer.data_bytes, b"\x11\xAA\x33")
            self.assertTrue(viewer.is_modified)
            viewer.set_data(b"")  # 清除 dirty,避免关闭窗口时弹保存提示
        finally:
            window.close()

    def test_hex_read_only_blocks_edit(self):
        from ui.hex_viewer import HexViewer

        viewer = HexViewer()
        try:
            viewer.set_data(b"readonly", read_only=True)
            self.assertFalse(viewer.apply_edit(0, b"R"))
            self.assertFalse(viewer.is_modified)
        finally:
            viewer.deleteLater()

    def test_embedded_file_scan(self):
        window = MainWindow()
        try:
            panel = window.file_panel
            data = png_bytes(trailing=zip_bytes())
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "nested.png")
                with open(path, "wb") as f:
                    f.write(data)
                panel.load_file(path)
            panel._scan_embedded()
            self.assertEqual(panel.embedded_table.rowCount(), 1)
            self.assertEqual(panel.embedded_table.item(0, 1).text(), "ZIP")
            self.assertEqual(int(panel.embedded_table.item(0, 2).text()), len(zip_bytes()))
        finally:
            window.close()

    def test_zip_panel_lists_entries(self):
        window = MainWindow()
        try:
            panel = window.zip_panel
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "a.zip")
                with open(path, "wb") as f:
                    f.write(zip_bytes())
                panel.load_file(path)
            self.assertEqual(panel.table.rowCount(), 1)
            self.assertEqual(panel.table.item(0, 0).text(), "flag.txt")
            self.assertIn("未发现伪加密", panel.log.toPlainText())
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

    def test_gif_frame_browser_and_lsb_frame(self):
        window = MainWindow()
        try:
            panel = window.image_panel
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "anim.gif")
                with open(path, "wb") as f:
                    f.write(THREE_FRAME_GIF)
                panel.load_file(path)
            self.assertEqual(len(panel._gif_frames), 3)
            self.assertEqual(panel.frame_combo.count(), 3)
            panel.frame_combo.setCurrentIndex(2)
            self.assertEqual(panel.lsb_frame.currentIndex(), 2)
            self.assertFalse(panel.frame_preview.pixmap().isNull())
            panel.lsb_frame.setCurrentIndex(1)
            self.assertEqual(panel.frame_combo.currentIndex(), 1)
            self.assertFalse(panel.frame_preview.pixmap().isNull())
        finally:
            window.close()

    def test_lsb_multichannel_options(self):
        window = MainWindow()
        try:
            panel = window.image_panel
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "img.png")
                with open(path, "wb") as f:
                    f.write(self._png_bytes())
                panel.load_file(path)
            # R/G/B/A 后面是 RGB,索引 4
            panel.lsb_channel.setCurrentIndex(4)
            panel.lsb_order.setCurrentIndex(panel.lsb_order.findData("lsb"))
            panel._on_extract()
            self.assertEqual(len(panel._extracted), 6)
            self.assertIn("RGB", panel.lsb_output.toPlainText())
        finally:
            window.close()

    def test_stegsolve_data_extract_ui(self):
        window = MainWindow()
        try:
            panel = window.image_panel
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "img.png")
                with open(path, "wb") as f:
                    f.write(self._png_bytes())
                panel.load_file(path)
            panel.stegsolve._on_extract()
            self.assertEqual(len(panel.stegsolve._extracted), 2)
            self.assertTrue(panel.stegsolve.btn_save_extract.isEnabled())
        finally:
            window.close()

    def test_audio_panel_lsb(self):
        window = MainWindow()
        try:
            panel = window.audio_panel
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "a.wav")
                with open(path, "wb") as f:
                    f.write(wav_lsb_bytes())
                panel.load_file(path)
            panel._on_extract()
            self.assertEqual(panel._extracted, b"flag{wav_lsb}")
            self.assertIn("flag{wav_lsb}", panel.output.toPlainText())
        finally:
            window.close()

    def test_image_tools_channel_and_xor(self):
        from core import imagetools

        image = QImage(2, 2, QImage.Format_RGB32)
        image.fill(QColor(10, 20, 30))
        channel = imagetools.channel_image(image, 0)
        self.assertEqual(channel.size(), image.size())
        xor = imagetools.xor_images(image, image)
        self.assertIsNotNone(xor)
        self.assertEqual(QColor(xor.pixel(0, 0)).red(), 0)
        self.assertEqual(len(imagetools.histogram(image)), 256)

    def test_png_chunk_table(self):
        window = MainWindow()
        try:
            panel = window.image_panel
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "text.png")
                with open(path, "wb") as f:
                    f.write(png_text_bytes())
                panel.load_file(path)
            self.assertGreaterEqual(panel.chunk_table.rowCount(), 4)
            texts = [
                panel.chunk_table.item(row, 4).text()
                for row in range(panel.chunk_table.rowCount())
            ]
            self.assertTrue(any("flag{png_text}" in text for text in texts))
        finally:
            window.close()

    def test_lsb_row_scan_ui(self):
        window = MainWindow()
        try:
            panel = window.image_panel
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "img.png")
                with open(path, "wb") as f:
                    f.write(self._png_bytes())
                panel.load_file(path)
            panel._on_row_scan()
            self.assertGreater(len(panel.row_scan_output.toPlainText().splitlines()), 0)
            self.assertIn("通道顺序", panel.row_scan_status.text())
        finally:
            window.close()

    def test_prepended_image_is_loaded(self):
        window = MainWindow()
        try:
            panel = window.image_panel
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "img.bin")
                with open(path, "wb") as f:
                    f.write(b"GARBAGE" + self._png_bytes())
                panel.load_file(path)
            self.assertEqual(panel._kind, "PNG")
            self.assertEqual(panel._prefix, 7)
            self.assertTrue(panel._pixels)
            self.assertIn("前置数据", panel.file_label.text())
        finally:
            window.close()


if __name__ == "__main__":
    unittest.main()
