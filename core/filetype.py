"""文件类型识别:magic bytes 特征表 + 扩展名伪造检测 + 尾随数据检测。"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from core import fileparse


@dataclass(frozen=True)
class Signature:
    name: str
    exts: tuple[str, ...]
    magic: bytes
    offset: int = 0
    extra: tuple[int, bytes] | None = None  # 额外校验:(偏移, 必须匹配的字节)


_SIGNATURES: tuple[Signature, ...] = (
    Signature("PNG", (".png",), b"\x89PNG\r\n\x1a\n"),
    Signature("JPEG", (".jpg", ".jpeg", ".jpe"), b"\xff\xd8\xff"),
    Signature("GIF", (".gif",), b"GIF87a"),
    Signature("GIF", (".gif",), b"GIF89a"),
    Signature("BMP", (".bmp", ".dib"), b"BM"),
    Signature("TIFF", (".tif", ".tiff"), b"II*\x00"),
    Signature("TIFF", (".tif", ".tiff"), b"MM\x00*"),
    Signature("WEBP", (".webp",), b"RIFF", 0, (8, b"WEBP")),
    Signature("WAV", (".wav",), b"RIFF", 0, (8, b"WAVE")),
    Signature("AVI", (".avi",), b"RIFF", 0, (8, b"AVI ")),
    Signature("ICO", (".ico",), b"\x00\x00\x01\x00"),
    Signature("PSD", (".psd",), b"8BPS"),
    Signature("ZIP", (".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".epub"),
              b"PK\x03\x04"),
    Signature("ZIP", (".zip",), b"PK\x05\x06"),
    Signature("ZIP", (".zip",), b"PK\x07\x08"),
    Signature("RAR", (".rar",), b"RAR!\x1a\x07"),
    Signature("7Z", (".7z",), b"7z\xbc\xaf\x27\x1c"),
    Signature("GZIP", (".gz", ".tgz"), b"\x1f\x8b\x08"),
    Signature("BZIP2", (".bz2",), b"BZh"),
    Signature("XZ", (".xz",), b"\xfd7zXZ\x00"),
    Signature("TAR", (".tar",), b"ustar", 257),
    Signature("PDF", (".pdf",), b"%PDF-"),
    Signature("ELF", (".elf", ".so", ""), b"\x7fELF"),
    Signature("PE", (".exe", ".dll", ".sys", ".scr"), b"MZ"),
    Signature("Mach-O", (".macho",), b"\xcf\xfa\xed\xfe"),
    Signature("Mach-O", (".macho",), b"\xce\xfa\xed\xfe"),
    Signature("SQLite", (".db", ".sqlite", ".sqlite3"), b"SQLite format 3\x00"),
    Signature("MP4", (".mp4", ".m4a", ".mov", ".heic", ".heif"), b"ftyp", 4),
    Signature("FLAC", (".flac",), b"fLaC"),
    Signature("OGG", (".ogg", ".opus"), b"OggS"),
    Signature("MIDI", (".mid", ".midi"), b"MThd"),
    Signature("MKV", (".mkv", ".webm"), b"\x1aE\xdf\xa3"),
    Signature("PCAP", (".pcap",), b"\xd4\xc3\xb2\xa1"),
    Signature("PCAP", (".pcap",), b"\xa1\xb2\xc3\xd4"),
    Signature("PCAPNG", (".pcapng",), b"\x0a\x0d\x0d\x0a"),
    Signature("Java Class", (".class",), b"\xca\xfe\xba\xbe"),
    Signature("Python 字节码", (".pyc",), b"\xcb\x0d\x0d\x0a"),
    Signature("Python 字节码", (".pyc",), b"\x6f\x0d\x0d\x0a"),
    Signature("WASM", (".wasm",), b"\x00asm"),
    Signature("OLE 复合文档", (".doc", ".xls", ".ppt", ".msi"), b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
    Signature("DICOM", (".dcm",), b"DICM", 128),
    Signature("Windows 快捷方式", (".lnk",), b"L\x00\x00\x00\x01\x14\x02\x00"),
    Signature("注册表配置单元", (".reg",), b"regf"),
)

# 解析器支持的逻辑类型 → 解析器 kind 名
_PARSE_KIND = {
    "PNG": "PNG", "JPEG": "JPEG", "GIF": "GIF", "BMP": "BMP", "ZIP": "ZIP",
}


@dataclass
class TrailingData:
    offset: int
    length: int
    hint: str = ""


@dataclass
class IdentifyResult:
    filename: str
    size: int
    declared_ext: str
    matches: list[str] = field(default_factory=list)
    real_name: str = "未知"
    real_ext: str = ""
    ext_ok: bool = True
    trailing: TrailingData | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def kind(self) -> str:
        return self.real_name


def _match(data: bytes) -> list[Signature]:
    hits: list[Signature] = []
    for sig in _SIGNATURES:
        if sig.offset + len(sig.magic) > len(data):
            continue
        if data[sig.offset:sig.offset + len(sig.magic)] != sig.magic:
            continue
        if sig.extra is not None:
            off, need = sig.extra
            if data[off:off + len(need)] != need:
                continue
        hits.append(sig)
    return hits


def _is_text(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:4096]
    printable = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(sample) >= 0.9


def identify(data: bytes, filename: str = "") -> IdentifyResult:
    """识别真实文件类型,并与扩展名比对。"""
    ext = os.path.splitext(filename)[1].lower() if filename else ""
    hit_names: list[str] = []
    hits = _match(data)
    for sig in hits:
        if sig.name not in hit_names:
            hit_names.append(sig.name)

    result = IdentifyResult(filename=filename, size=len(data), declared_ext=ext,
                            matches=hit_names)

    if hits:
        primary = hits[0]
        result.real_name = primary.name
        result.real_ext = primary.exts[0] if primary.exts else ""
        # 扩展名是否合法(允许无扩展名)
        allowed = set()
        for sig in hits:
            allowed.update(sig.exts)
        result.ext_ok = (not ext) or (ext in allowed)
        if ext and not result.ext_ok:
            result.notes.append(
                f"扩展名 {ext} 与真实类型 {primary.name} 不符,可能是伪造扩展名;"
                f"建议改为 {result.real_ext}"
            )
    elif _is_text(data):
        result.real_name = "纯文本"
        result.real_ext = ".txt"
        result.ext_ok = ext in ("", ".txt", ".md", ".csv", ".json", ".xml", ".html")
        if not result.ext_ok:
            result.notes.append(f"扩展名 {ext} 但内容是纯文本,可能是改了扩展名的文本文件")
    else:
        result.real_name = "未知二进制"
        result.real_ext = ""
        result.notes.append("未命中任何已知 magic bytes,可能是加密数据或自定义格式")
        # 高熵提示
        if len(data) > 256 and fileparse_entropy(data[:65536]) > 7.5:
            result.notes.append("前 64KB 熵值 >7.5,疑似加密/压缩数据")

    # 尾随数据检测
    kind = _PARSE_KIND.get(result.real_name)
    if kind:
        end = fileparse.logical_end(kind, data)
        if end is not None and end < len(data):
            tail = data[end:]
            hint = _tail_hint(tail)
            result.trailing = TrailingData(end, len(data) - end, hint)
            result.notes.append(f"文件逻辑结束于 {end},尾部有 {len(data) - end} 字节附加数据{hint}")
            if result.real_name == "ZIP":
                result.notes.append("ZIP 尾部附加数据:可能是压缩包注释或隐藏文件")
    return result


def fileparse_entropy(data: bytes) -> float:
    """局部导入避免循环依赖,计算字节熵。"""
    from core.analysis import entropy

    return entropy(data)


def _tail_hint(tail: bytes) -> str:
    stripped = tail.lstrip(b"\x00 \r\n\t")
    if stripped.startswith(b"PK\x03\x04"):
        return "(尾部疑似内嵌 ZIP)"
    if stripped[:8] == b"\x89PNG\r\n\x1a\n":
        return "(尾部疑似内嵌 PNG)"
    if stripped[:3] == b"\xff\xd8\xff":
        return "(尾部疑似内嵌 JPEG)"
    if stripped[:6] in (b"GIF87a", b"GIF89a"):
        return "(尾部疑似内嵌 GIF)"
    if stripped.isascii() and stripped.strip():
        return f"(ASCII 内容: {stripped[:40].decode('ascii', 'replace')!r})"
    return ""


def identify_file(path: str) -> IdentifyResult:
    """读取整个文件并识别(尾随数据检测需要完整内容)。"""
    with open(path, "rb") as f:
        data = f.read()
    return identify(data, os.path.basename(path))
