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


@dataclass(frozen=True)
class Hit:
    """一次实际命中:签名 + magic 在文件中的真实偏移。"""

    signature: Signature
    offset: int


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

# 允许在文件头前部扫描的“强签名”。弱签名(BM/MZ 等)不参与扫描,
# 否则普通文本里的两个字母就会造成误报。
_PREFIX_SCAN_NAMES = {
    "PNG", "JPEG", "GIF", "ZIP", "RAR", "7Z", "GZIP", "BZIP2", "XZ",
    "PDF", "ELF", "SQLite", "FLAC", "OGG", "MIDI", "MKV", "PCAP",
    "PCAPNG", "Java Class", "WASM", "OLE 复合文档", "WEBP", "WAV", "AVI",
}

_PREFIX_SCAN_LIMIT = 4096


@dataclass
class TrailingData:
    offset: int
    length: int
    hint: str = ""


@dataclass
class HeaderCheck:
    """文件头检测结果:实际字节 vs 期望 magic。"""

    offset: int
    expected: bytes
    actual: bytes
    matched: bool
    name: str = ""

    @property
    def expected_hex(self) -> str:
        return " ".join(f"{b:02X}" for b in self.expected) or "(未知)"

    @property
    def actual_hex(self) -> str:
        return " ".join(f"{b:02X}" for b in self.actual)


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
    header: HeaderCheck | None = None
    notes: list[str] = field(default_factory=list)
    prefix: int = 0
    text_encoding: str = ""

    @property
    def kind(self) -> str:
        return self.real_name


def _u16le(data: bytes, pos: int) -> int:
    return int.from_bytes(data[pos:pos + 2], "little")


def _u32le(data: bytes, pos: int) -> int:
    return int.from_bytes(data[pos:pos + 4], "little")


def _valid_bmp(data: bytes, off: int) -> bool:
    """BM 只有两字节,必须继续检查 DIB 头,避免把 "BMW..." 当位图。"""
    if off + 26 > len(data):
        return False
    declared_size = _u32le(data, off + 2)
    pixel_off = _u32le(data, off + 10)
    dib_size = _u32le(data, off + 14)
    if dib_size < 12 or dib_size > 4096:
        return False
    if dib_size != 12 and off + 30 > len(data):
        return False
    if pixel_off < 14 or pixel_off > max(len(data), declared_size):
        return False
    if declared_size and declared_size < pixel_off:
        return False
    if dib_size == 12:  # OS/2 BITMAPCOREHEADER:宽高是 16 位
        width = _u16le(data, off + 18)
        height = _u16le(data, off + 20)
        bpp = _u16le(data, off + 24)
    else:
        width = int.from_bytes(data[off + 18:off + 22], "little", signed=True)
        height = int.from_bytes(data[off + 22:off + 26], "little", signed=True)
        bpp = _u16le(data, off + 28)
    if width <= 0 or height == 0:
        return False
    if bpp not in (1, 2, 4, 8, 16, 24, 32, 64):
        return False
    return True


def _valid_pe(data: bytes, off: int) -> bool:
    """MZ 同样太弱,要求 e_lfanew 指向 PE\0\0。"""
    if off + 0x40 > len(data):
        return False
    lfanew = _u32le(data, off + 0x3C)
    if lfanew < 0x40 or off + lfanew + 4 > len(data):
        return False
    return data[off + lfanew:off + lfanew + 4] == b"PE\x00\x00"


def _valid_mp4(data: bytes, off: int) -> bool:
    """off 指向 ftyp,box size 在它前面 4 字节。"""
    box = off - 4
    if box < 0 or off + 8 > len(data):
        return False
    size = int.from_bytes(data[box:box + 4], "big")
    if size != 0 and (size < 8 or size > len(data) - box):
        return False
    brand = data[off + 4:off + 8]
    return all(32 <= b <= 126 for b in brand)


def _valid_tar(data: bytes, off: int) -> bool:
    """校验 tar header 的 checksum,避免任意位置出现 ustar 就误报。"""
    base = off - 257
    if base < 0 or base + 512 > len(data):
        return False
    header = data[base:base + 512]
    stored = header[148:156].strip(b"\x00 ")
    try:
        expected = int(stored, 8)
    except ValueError:
        return False
    actual = sum(header[:148]) + 8 * 32 + sum(header[156:])
    return stored not in (b"", b"0") and expected == actual


def _valid_hit(sig: Signature, data: bytes, off: int) -> bool:
    if sig.name == "BMP":
        return _valid_bmp(data, off)
    if sig.name == "PE":
        return _valid_pe(data, off)
    if sig.name == "MP4":
        return _valid_mp4(data, off)
    if sig.name == "TAR":
        return _valid_tar(data, off)
    return True


def _hit_at(data: bytes, sig: Signature, off: int) -> Hit | None:
    if off < 0 or off + len(sig.magic) > len(data):
        return None
    if data[off:off + len(sig.magic)] != sig.magic:
        return None
    if sig.extra is not None:
        extra_off, need = sig.extra
        pos = off + extra_off
        if data[pos:pos + len(need)] != need:
            return None
    if not _valid_hit(sig, data, off):
        return None
    return Hit(sig, off)


def _match(data: bytes) -> list[Hit]:
    hits: list[Hit] = []
    for sig in _SIGNATURES:
        hit = _hit_at(data, sig, sig.offset)
        if hit is not None:
            hits.append(hit)
    return hits


def _prefix_match(data: bytes) -> list[Hit]:
    """在文件头前 4KB 内寻找强签名,用于识别被前置垃圾数据包裹的文件。"""
    hits: list[Hit] = []
    seen: set[str] = set()
    limit = min(len(data), _PREFIX_SCAN_LIMIT)
    for sig in _SIGNATURES:
        if sig.offset != 0 or sig.name not in _PREFIX_SCAN_NAMES or sig.name in seen:
            continue
        start = 1
        while start < limit:
            off = data.find(sig.magic, start, limit)
            if off < 0:
                break
            hit = _hit_at(data, sig, off)
            if hit is not None:
                hits.append(hit)
                seen.add(sig.name)
                break
            start = off + 1
    hits.sort(key=lambda hit: hit.offset)
    return hits


def _text_encoding(data: bytes) -> tuple[bool, str]:
    """识别常见文本编码,支持中文 UTF-8 / UTF-16 / GB18030。"""
    if not data:
        return False, ""
    sample = data[:4096]
    candidates: list[tuple[str, bytes]] = []
    if sample.startswith(b"\xef\xbb\xbf"):
        candidates.append(("UTF-8 BOM", sample))
    elif sample.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        candidates.append(("UTF-32", sample))
    elif sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        candidates.append(("UTF-16", sample))
    # 无 BOM 时用零字节位置判断 UTF-16 端序:BE 的零字节在偶数位,LE 在奇数位。
    even_zeros = sample[0::2].count(0)
    odd_zeros = sample[1::2].count(0)
    utf16_order = ["UTF-16 LE", "UTF-16 BE"]
    if even_zeros > odd_zeros * 2 and even_zeros >= max(1, len(sample) // 8):
        utf16_order = ["UTF-16 BE", "UTF-16 LE"]
    elif odd_zeros > even_zeros * 2 and odd_zeros >= max(1, len(sample) // 8):
        utf16_order = ["UTF-16 LE", "UTF-16 BE"]
    candidates.extend([
        ("UTF-8", sample),
        ("GB18030", sample),
        (utf16_order[0], sample),
        (utf16_order[1], sample),
    ])
    for name, raw in candidates:
        try:
            if name == "UTF-8 BOM":
                text = raw.decode("utf-8-sig")
            elif name == "UTF-32":
                text = raw.decode("utf-32")
            elif name == "UTF-16":
                text = raw.decode("utf-16")
            elif name == "UTF-16 LE":
                if len(raw) % 2:
                    raw = raw[:-1]
                text = raw.decode("utf-16-le")
            elif name == "UTF-16 BE":
                if len(raw) % 2:
                    raw = raw[:-1]
                text = raw.decode("utf-16-be")
            elif name == "GB18030":
                if not any(b >= 0x80 for b in raw):
                    continue
                text = raw.decode("gb18030")
            else:
                text = raw.decode("utf-8")
        except (UnicodeDecodeError, LookupError):
            continue
        if not text:
            continue
        if name in ("UTF-16 LE", "UTF-16 BE"):
            zero_ratio = sum(1 for b in sample if b == 0) / max(1, len(sample))
            cjk_ratio = sum("\u4e00" <= ch <= "\u9fff" for ch in text) / len(text)
            if zero_ratio < 0.15 and cjk_ratio < 0.5:
                continue
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in text):
            continue
        printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
        if printable / len(text) >= 0.92 and "\x00" not in text:
            return True, name
    return False, ""


def _is_text(data: bytes) -> bool:
    return _text_encoding(data)[0]


def identify(data: bytes, filename: str = "") -> IdentifyResult:
    """识别真实文件类型,并与扩展名比对。"""
    ext = os.path.splitext(filename)[1].lower() if filename else ""
    normal_hits = _match(data)
    hits = normal_hits or _prefix_match(data)
    hit_names: list[str] = []
    for hit in hits:
        if hit.signature.name not in hit_names:
            hit_names.append(hit.signature.name)

    result = IdentifyResult(filename=filename, size=len(data), declared_ext=ext,
                            matches=hit_names)

    if hits:
        primary = hits[0]
        result.real_name = primary.signature.name
        result.real_ext = primary.signature.exts[0] if primary.signature.exts else ""
        result.prefix = primary.offset
        # 扩展名是否合法(允许无扩展名)
        allowed = set()
        for hit in hits:
            allowed.update(hit.signature.exts)
        result.ext_ok = (not ext) or (ext in allowed)
        if ext and not result.ext_ok:
            result.notes.append(
                f"扩展名 {ext} 与真实类型 {primary.signature.name} 不符,可能是伪造扩展名;"
                f"建议改为 {result.real_ext}"
            )
        if primary.offset > 0:
            result.notes.append(
                f"真实 {primary.signature.name} 文件头位于 offset {primary.offset},"
                f"前面有 {primary.offset} 字节前置数据"
            )
    elif _is_text(data):
        result.real_name = "纯文本"
        result.real_ext = ".txt"
        result.text_encoding = _text_encoding(data)[1]
        result.ext_ok = ext in ("", ".txt", ".md", ".csv", ".json", ".xml", ".html")
        if not result.ext_ok:
            result.notes.append(f"扩展名 {ext} 但内容是纯文本,可能是改了扩展名的文本文件")
        if result.text_encoding not in ("", "UTF-8"):
            result.notes.append(f"文本编码推测:{result.text_encoding}")
    else:
        result.real_name = "未知二进制"
        result.real_ext = ""
        result.notes.append("未命中任何已知 magic bytes,可能是加密数据或自定义格式")
        # 高熵提示
        if len(data) > 256 and fileparse_entropy(data[:65536]) > 7.5:
            result.notes.append("前 64KB 熵值 >7.5,疑似加密/压缩数据")

    # 文件头检测:命中签名时给出期望 magic 与实际字节
    if hits:
        primary = hits[0]
        result.header = HeaderCheck(
            primary.offset, primary.signature.magic,
            data[primary.offset:primary.offset + len(primary.signature.magic)],
            True, primary.signature.name,
        )
    else:
        result.header = HeaderCheck(0, b"", data[:16], False, result.real_name)

    # 尾随数据检测(前置数据需要从真实 magic 位置开始解析)
    kind = _PARSE_KIND.get(result.real_name)
    if kind:
        payload = data[result.prefix:]
        end = fileparse.logical_end(kind, payload)
        if end is not None:
            end += result.prefix
            if end < len(data):
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
