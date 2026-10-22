"""轻量级文件嵌套检测(binwalk 风格)。

不是 binwalk 的替代品:只扫描常见强 magic,估算内嵌文件长度,并支持
单文件/批量提取。完整签名库、递归解包、损坏文件修复请交给 Kali 的
binwalk/foremost。
"""

from __future__ import annotations

import io
import os
import zipfile
from dataclasses import dataclass

from core import fileparse

# (显示名, magic, 建议扩展名, 类型)
_MAGIC: tuple[tuple[str, bytes, str, str], ...] = (
    ("PNG", b"\x89PNG\r\n\x1a\n", ".png", "png"),
    ("JPEG", b"\xff\xd8\xff", ".jpg", "jpeg"),
    ("GIF87a", b"GIF87a", ".gif", "gif"),
    ("GIF89a", b"GIF89a", ".gif", "gif"),
    ("ZIP", b"PK\x03\x04", ".zip", "zip"),
    ("RAR", b"RAR!\x1a\x07", ".rar", "rar"),
    ("7Z", b"7z\xbc\xaf\x27\x1c", ".7z", "7z"),
    ("GZIP", b"\x1f\x8b\x08", ".gz", "gzip"),
    ("BZIP2", b"BZh", ".bz2", "bzip2"),
    ("XZ", b"\xfd7zXZ\x00", ".xz", "xz"),
    ("PDF", b"%PDF-", ".pdf", "pdf"),
    ("ELF", b"\x7fELF", ".elf", "elf"),
    ("SQLite", b"SQLite format 3\x00", ".sqlite", "sqlite"),
    ("FLAC", b"fLaC", ".flac", "flac"),
    ("OGG", b"OggS", ".ogg", "ogg"),
    ("PCAP", b"\xd4\xc3\xb2\xa1", ".pcap", "pcap"),
    ("PCAP", b"\xa1\xb2\xc3\xd4", ".pcap", "pcap"),
    ("PCAPNG", b"\x0a\x0d\x0d\x0a", ".pcapng", "pcapng"),
    ("Java Class", b"\xca\xfe\xba\xbe", ".class", "java"),
    ("WASM", b"\x00asm", ".wasm", "wasm"),
    ("OLE", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", ".doc", "ole"),
)


@dataclass
class EmbeddedFile:
    offset: int
    end: int
    kind: str
    ext: str
    detail: str = ""
    known_size: bool = True

    @property
    def size(self) -> int:
        return max(0, self.end - self.offset)


def _zip_detail(blob: bytes) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            names = zf.namelist()
            return f"ZIP,{len(names)} 个条目"
    except (zipfile.BadZipFile, OSError):
        return "ZIP(目录损坏)"


def _estimate_end(data: bytes, offset: int, kind: str) -> int | None:
    blob = data[offset:]
    try:
        if kind == "png":
            parsed = fileparse.parse_png(blob)
            if parsed and parsed[1] > 8:
                return offset + parsed[1]
        elif kind == "jpeg":
            parsed = fileparse.parse_jpg(blob)
            if parsed and parsed[1] > 2:
                return offset + parsed[1]
        elif kind == "gif":
            parsed = fileparse.parse_gif(blob)
            if parsed and parsed[1] > 13:
                return offset + parsed[1]
        elif kind == "zip":
            parsed = fileparse.parse_zip(blob)
            if parsed and parsed[0] and parsed[1] > 4:
                return offset + parsed[1]
        elif kind == "pdf":
            eof = blob.find(b"%%EOF", 0, 64 * 1024 * 1024)
            if eof >= 0:
                return offset + eof + 5
    except (IndexError, ValueError):
        return None
    return None


def _looks_like_mp4(data: bytes, off: int) -> bool:
    if off < 0 or off + 8 > len(data):
        return False
    size = int.from_bytes(data[off:off + 4], "big")
    if size != 0 and (size < 8 or size > len(data) - off):
        return False
    brand = data[off + 4:off + 8]
    return all(32 <= b <= 126 for b in brand)


def scan_embedded(data: bytes, scan_limit: int = 64 * 1024 * 1024,
                  max_results: int = 200) -> list[EmbeddedFile]:
    """扫描内嵌文件;只返回 offset > 0 的命中,不把文件自身算进去。"""
    if not data:
        return []
    limit = min(len(data), scan_limit)
    hits: list[tuple[int, str, str, str]] = []
    for name, magic, ext, kind in _MAGIC:
        start = 0
        while True:
            off = data.find(magic, start, limit)
            if off < 0:
                break
            if off > 0 and not (
                    kind == "bzip2" and (off + 3 >= len(data)
                                         or data[off + 3:off + 4] not in b"123456789")):
                hits.append((off, name, ext, kind))
            start = off + max(1, len(magic))
        if len(hits) >= max_results * 2:
            break

    # MP4 的 ftyp 在 box 头后 4 字节,单独判断一次。
    start = 0
    while True:
        ftyp = data.find(b"ftyp", start, limit)
        if ftyp < 0:
            break
        off = ftyp - 4
        if off > 0 and _looks_like_mp4(data, off):
            hits.append((off, "MP4", ".mp4", "mp4"))
        start = ftyp + 4

    hits.sort(key=lambda item: item[0])
    results: list[EmbeddedFile] = []
    last_end = 0
    for off, name, ext, kind in hits:
        if off <= last_end:
            continue
        end = _estimate_end(data, off, kind)
        known = end is not None
        if end is None:
            # 未知长度:先以文件尾为界,UI 会标注“长度未知”。
            next_off = next((item[0] for item in hits if item[0] > off), len(data))
            end = min(len(data), next_off if next_off > off else len(data))
        if end <= off:
            continue
        blob = data[off:end]
        if kind == "zip":
            detail = _zip_detail(blob)
        else:
            detail = name
        results.append(EmbeddedFile(off, end, name, ext, detail, known))
        last_end = end
        if len(results) >= max_results:
            break
    return results


def extract(data: bytes, item: EmbeddedFile) -> bytes:
    return data[item.offset:item.end]


def suggested_name(item: EmbeddedFile, index: int = 0) -> str:
    return f"embedded_{index:02d}_{item.offset:X}{item.ext}"


def safe_name(name: str) -> str:
    """去掉路径分隔符,防止把提取结果写到目录外。"""
    return os.path.basename(name).replace(":", "_") or "embedded.bin"
