"""ZIP 辅助:结构检查、伪加密检测/修复、密码恢复与 CRC32 反查。

bkcrack 已知明文攻击不在这里实现,而是通过 core/bkcrack.py 调用外部
bkcrack.exe。本模块只负责 ZIP 结构、ZipCrypto 字典/暴力/掩码恢复,以及
针对极小加密条目的 CRC32 明文反查。
"""

from __future__ import annotations

import binascii
import itertools
import os
import threading
import time
import zipfile
import zlib
from dataclasses import dataclass, field
from typing import Callable, Iterator

from core import fileparse

_LOCAL = b"PK\x03\x04"
_CENTRAL = b"PK\x01\x02"

DEFAULT_WILDCARD = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

WILDCARD_OPTIONS: tuple[tuple[str, str, str], ...] = (
    ("l", "小写字母", "abcdefghijklmnopqrstuvwxyz"),
    ("u", "大写字母", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    ("d", "数字", "0123456789"),
    ("H", "大写 HEX", "0123456789ABCDEF"),
    ("h", "小写 HEX", "0123456789abcdef"),
    ("s", "特殊符号", "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"),
    ("a", "所有可打印字符", "".join(chr(i) for i in range(32, 127))),
)
_WILDCARD_CHARS = {code: chars for code, _label, chars in WILDCARD_OPTIONS}

MAX_EXTRACT_ENTRIES = 10_000
MAX_EXTRACT_SINGLE = 512 * 1024 * 1024
MAX_EXTRACT_TOTAL = 2 * 1024 * 1024 * 1024
MAX_EXTRACT_RATIO = 1000
HARD_EXTRACT_SINGLE = 2 * 1024 * 1024 * 1024
HARD_EXTRACT_TOTAL = 8 * 1024 * 1024 * 1024


@dataclass
class ZipEntry:
    name: str
    flags: int
    method: int
    crc: int
    compressed_size: int
    size: int
    local_offset: int
    central_offset: int
    local_flags: int | None = None
    aes: bool = False
    pseudo: bool = False
    reason: str = ""


@dataclass
class ZipInspect:
    comment: str = ""
    entries: list[ZipEntry] = field(default_factory=list)
    error: str = ""


def _decode_name(raw: bytes, flags: int) -> str:
    try:
        return raw.decode("utf-8" if flags & 0x800 else "gbk", "replace")
    except LookupError:
        return raw.decode("utf-8", "replace")


def _has_aes_extra(extra: bytes) -> bool:
    """检查 WinZip AES extra field 0x9901。Python zipfile 不支持 AES 解密。"""
    pos = 0
    while pos + 4 <= len(extra):
        tag = int.from_bytes(extra[pos:pos + 2], "little")
        size = int.from_bytes(extra[pos + 2:pos + 4], "little")
        if tag == 0x9901:
            return True
        pos += 4 + size
    return False


def _try_plain_data(data: bytes, entry: ZipEntry) -> bool:
    """在“两边都置了加密位”时,尝试直接解压判断是否其实没加密。"""
    header = entry.local_offset
    if header < 0 or header + 30 > len(data) or data[header:header + 4] != _LOCAL:
        return False
    nlen = int.from_bytes(data[header + 26:header + 28], "little")
    elen = int.from_bytes(data[header + 28:header + 30], "little")
    start = header + 30 + nlen + elen
    end = start + entry.compressed_size
    if end > len(data) or entry.compressed_size == 0:
        return False
    payload = data[start:end]
    try:
        if entry.method == 0:
            plain = payload
        elif entry.method == 8:
            dec = zlib.decompressobj(-15)
            plain = dec.decompress(payload, 16 * 1024 * 1024)
            if dec.unconsumed_tail:
                return False
        else:
            return False
    except zlib.error:
        return False
    return (binascii.crc32(plain) & 0xFFFFFFFF) == entry.crc


def inspect(data: bytes) -> ZipInspect:
    """读取中央目录并检测伪加密。"""
    result = ZipInspect()
    eocd = fileparse._find_zip_eocd(data)
    if eocd < 0:
        result.error = "找不到有效的 ZIP EOCD"
        return result
    total = int.from_bytes(data[eocd + 10:eocd + 12], "little")
    cd_size = int.from_bytes(data[eocd + 12:eocd + 16], "little")
    cd_off = int.from_bytes(data[eocd + 16:eocd + 20], "little")
    comment_len = int.from_bytes(data[eocd + 20:eocd + 22], "little")
    if total == 0xFFFF or cd_size == 0xFFFFFFFF or cd_off == 0xFFFFFFFF:
        z = fileparse._zip64_values(data, eocd)
        if z is not None:
            total, cd_size, cd_off = z
    if comment_len:
        raw = data[eocd + 22:eocd + 22 + comment_len]
        try:
            result.comment = raw.decode("utf-8")
        except UnicodeDecodeError:
            result.comment = raw.decode("gb18030", "replace")
    base = fileparse.zip_data_base(data, eocd)
    pos = base + cd_off
    for _ in range(min(total, 100000)):
        if pos + 46 > len(data) or data[pos:pos + 4] != _CENTRAL:
            break
        flags = int.from_bytes(data[pos + 8:pos + 10], "little")
        method = int.from_bytes(data[pos + 10:pos + 12], "little")
        crc = int.from_bytes(data[pos + 16:pos + 20], "little")
        csize = int.from_bytes(data[pos + 20:pos + 24], "little")
        usize = int.from_bytes(data[pos + 24:pos + 28], "little")
        nlen = int.from_bytes(data[pos + 28:pos + 30], "little")
        elen = int.from_bytes(data[pos + 30:pos + 32], "little")
        clen = int.from_bytes(data[pos + 32:pos + 34], "little")
        lho = int.from_bytes(data[pos + 42:pos + 46], "little")
        name = _decode_name(data[pos + 46:pos + 46 + nlen], flags)
        extra_off = pos + 46 + nlen
        extra = data[extra_off:extra_off + elen]
        entry = ZipEntry(name, flags, method, crc, csize, usize,
                         base + lho, pos)
        entry.aes = bool(flags & 1) and (method == 99 or _has_aes_extra(extra))
        if lho + 30 <= len(data) and data[lho:lho + 4] == _LOCAL:
            entry.local_flags = int.from_bytes(data[lho + 6:lho + 8], "little")
            if bool(entry.local_flags & 1) != bool(flags & 1):
                entry.pseudo = True
                entry.reason = "本地头与中央目录的加密标志位不一致"
            elif flags & 1 and _try_plain_data(data, entry):
                entry.pseudo = True
                entry.reason = "两边都标记加密,但数据实际可以无密码解压"
        result.entries.append(entry)
        pos += 46 + nlen + elen + clen
    return result


def repair_pseudo_encryption(data: bytes) -> tuple[bytes, int]:
    """清除伪加密条目的 bit0;返回 (新数据, 修复条目数)。"""
    info = inspect(data)
    out = bytearray(data)
    count = 0
    for entry in info.entries:
        if not entry.pseudo:
            continue
        out[entry.central_offset + 8] &= 0xFE
        if (entry.local_offset + 30 <= len(out)
                and out[entry.local_offset:entry.local_offset + 4] == _LOCAL):
            out[entry.local_offset + 6] &= 0xFE
        count += 1
    return bytes(out), count


def extraction_risks(entries: list[zipfile.ZipInfo]) -> list[str]:
    """Return resource-limit warnings for an archive's declared contents."""
    risks: list[str] = []
    if len(entries) > MAX_EXTRACT_ENTRIES:
        risks.append(
            f"条目数 {len(entries):,} 超过安全上限 {MAX_EXTRACT_ENTRIES:,}")
    total = sum(max(0, entry.file_size) for entry in entries)
    if total > MAX_EXTRACT_TOTAL:
        risks.append(
            f"解压总量 {total / 1024 / 1024:.1f} MB 超过 "
            f"{MAX_EXTRACT_TOTAL // 1024 // 1024} MB")
    for entry in entries:
        if entry.file_size > MAX_EXTRACT_SINGLE:
            risks.append(
                f"条目 {entry.filename!r} 解压后 "
                f"{entry.file_size / 1024 / 1024:.1f} MB,超过单文件上限")
            break
    for entry in entries:
        if entry.compress_size and entry.file_size >= 1024 * 1024:
            ratio = entry.file_size / entry.compress_size
            if ratio > MAX_EXTRACT_RATIO:
                risks.append(
                    f"条目 {entry.filename!r} 压缩比 {ratio:.0f}:1,"
                    f"超过 {MAX_EXTRACT_RATIO}:1")
                break
    return risks


def safe_extract_path(root: str, name: str) -> str | None:
    """Resolve an archive member only when it stays under root."""
    root_path = os.path.realpath(root)
    destination = os.path.realpath(os.path.join(root_path, name))
    try:
        if os.path.commonpath([root_path, destination]) == root_path:
            return destination
    except ValueError:
        pass
    return None


# ---------------------------------------------------------------- CRC32 反查

MAX_CRC_ARCHIVE_BYTES = 1024 * 1024
MAX_CRC_ENTRIES = 256
MAX_CRC_ENTRY_BYTES = 6
MAX_CRC_SOLUTIONS = 65_536


@dataclass
class CrcSolve:
    candidates: list[bytes] = field(default_factory=list)
    total: int = 0
    truncated: bool = False
    cancelled: bool = False


@dataclass
class CrcBruteResult:
    candidates: list[bytes] = field(default_factory=list)
    tried: int = 0
    elapsed: float = 0.0
    cancelled: bool = False
    error: str = ""
    entry_name: str = ""
    entry_index: int = -1
    size: int = 0
    method: int = 0
    compressed_size: int = 0


def _solve_crc_linear(target: int, length: int) -> tuple[int, list[int]] | None:
    """Solve CRC32(data) == target for a fixed byte length over GF(2)."""
    zero = b"\x00" * length
    base = zlib.crc32(zero) & 0xFFFFFFFF
    rhs = (target ^ base) & 0xFFFFFFFF
    nvars = length * 8
    columns: list[int] = []
    for index in range(length):
        for bit in range(8):
            buf = bytearray(zero)
            buf[index] = 1 << bit
            columns.append((zlib.crc32(bytes(buf)) & 0xFFFFFFFF) ^ base)

    rows: list[list[int]] = []
    for out_bit in range(32):
        mask = 0
        for var, column in enumerate(columns):
            if (column >> out_bit) & 1:
                mask |= 1 << var
        rows.append([mask, (rhs >> out_bit) & 1])

    pivots: dict[int, int] = {}
    rank = 0
    for col in range(nvars):
        pivot = next(
            (row for row in range(rank, 32) if (rows[row][0] >> col) & 1),
            None,
        )
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        for row in range(32):
            if row != rank and (rows[row][0] >> col) & 1:
                rows[row][0] ^= rows[rank][0]
                rows[row][1] ^= rows[rank][1]
        pivots[col] = rank
        rank += 1

    for row in range(rank, 32):
        if rows[row][0] == 0 and rows[row][1]:
            return None

    particular = 0
    for col, row in pivots.items():
        if rows[row][1]:
            particular |= 1 << col

    free_columns = [col for col in range(nvars) if col not in pivots]
    basis: list[int] = []
    for free in free_columns:
        vector = 1 << free
        for col, row in pivots.items():
            if (rows[row][0] >> free) & 1:
                vector |= 1 << col
        basis.append(vector)
    return particular, basis


def crc32_preimages(target: int, length: int,
                    cancel: threading.Event | None = None,
                    progress: Callable[[int, int], None] | None = None
                    ) -> CrcSolve:
    """Return all byte strings of ``length`` bytes whose CRC32 equals target."""
    result = CrcSolve()
    if length < 0 or length > MAX_CRC_ENTRY_BYTES:
        result.truncated = True
        return result
    if length == 0:
        result.total = 1
        if target == 0:
            result.candidates.append(b"")
        return result

    solved = _solve_crc_linear(target & 0xFFFFFFFF, length)
    if solved is None:
        return result
    particular, basis = solved
    total = 1 << len(basis)
    result.total = total
    if total > MAX_CRC_SOLUTIONS:
        result.truncated = True
        return result

    vector = particular
    for index in range(total):
        if cancel is not None and cancel.is_set():
            result.cancelled = True
            break
        if index:
            # Gray code order: flip exactly one basis vector per step.
            bit = (index & -index).bit_length() - 1
            vector ^= basis[bit]
        data = bytearray(length)
        for var in range(length * 8):
            if (vector >> var) & 1:
                data[var >> 3] |= 1 << (var & 7)
        candidate = bytes(data)
        if (zlib.crc32(candidate) & 0xFFFFFFFF) == (target & 0xFFFFFFFF):
            result.candidates.append(candidate)
        if progress is not None and (index + 1 == total or (index + 1) % 4096 == 0):
            progress(index + 1, total)
    return result


def crc32_bruteforce(data: bytes, entry_index: int = 0,
                     cancel: threading.Event | None = None,
                     progress: Callable[[int, int], None] | None = None
                     ) -> CrcBruteResult:
    """Recover a tiny ZipCrypto entry's plaintext from its stored CRC32.

    Only very small archives and entries are accepted; the function never
    writes or executes data.  It is meant for tiny CTF files (typically 4
    bytes), where the 32-bit CRC is enough to determine the plaintext.
    """
    started = time.monotonic()
    result = CrcBruteResult(entry_index=entry_index)
    if not data:
        result.error = "ZIP 数据为空"
        return result
    if len(data) > MAX_CRC_ARCHIVE_BYTES:
        result.error = (
            f"ZIP 文件 {len(data):,} 字节,超过 CRC 爆破安全上限 "
            f"{MAX_CRC_ARCHIVE_BYTES:,} 字节;该功能只用于极小的 ZIP")
        return result
    info = inspect(data)
    if info.error:
        result.error = info.error
        return result
    if len(info.entries) > MAX_CRC_ENTRIES:
        result.error = (
            f"ZIP 条目数 {len(info.entries):,} 超过安全上限 "
            f"{MAX_CRC_ENTRIES:,}")
        return result
    if entry_index < 0 or entry_index >= len(info.entries):
        result.error = "请选择要爆破的加密条目"
        return result
    entry = info.entries[entry_index]
    result.entry_name = entry.name
    result.size = entry.size
    result.method = entry.method
    result.compressed_size = entry.compressed_size

    if entry.aes:
        result.error = "该条目使用 AES/WinZip 加密,CRC32 反查不适用"
        return result
    if entry.flags & 0x40:
        result.error = "该条目使用 Strong Encryption(bit 6),CRC32 反查不适用"
        return result
    if not (entry.flags & 1):
        result.error = "该条目未加密,无需 CRC 爆破"
        return result
    if entry.pseudo:
        result.error = "该条目疑似伪加密,请先修复伪加密"
        return result
    if entry.size > MAX_CRC_ENTRY_BYTES:
        result.error = (
            f"条目明文 {entry.size:,} 字节,超过 CRC 爆破上限 "
            f"{MAX_CRC_ENTRY_BYTES} 字节;更大的文件请使用已知明文攻击")
        return result
    if entry.method not in (0, 8):
        result.error = f"暂不支持压缩方法 {entry.method};仅支持存储/Deflate"
        return result
    if entry.compressed_size < 12:
        result.error = "加密数据长度异常,缺少 ZipCrypto 12 字节头"
        return result
    if entry.local_flags is None or not (entry.local_flags & 1):
        result.error = "本地头未标记加密,无法确认 ZipCrypto 条目"
        return result
    local = entry.local_offset
    if (local < 0 or local + 30 > len(data)
            or data[local:local + 4] != _LOCAL):
        result.error = "本地文件头越界或损坏"
        return result
    name_len = int.from_bytes(data[local + 26:local + 28], "little")
    extra_len = int.from_bytes(data[local + 28:local + 30], "little")
    start = local + 30 + name_len + extra_len
    if start + entry.compressed_size > len(data):
        result.error = "加密数据越过文件末尾"
        return result
    if entry.method == 0 and entry.compressed_size != entry.size + 12:
        result.error = "存储条目的加密后大小与明文大小不一致"
        return result

    solved = crc32_preimages(entry.crc, entry.size, cancel=cancel,
                             progress=progress)
    result.tried = solved.total
    result.cancelled = solved.cancelled
    if solved.truncated:
        result.error = (
            f"候选空间 {solved.total:,} 超过安全上限 "
            f"{MAX_CRC_SOLUTIONS:,}")
        return result
    result.candidates = solved.candidates
    result.elapsed = time.monotonic() - started
    return result


# ---------------------------------------------------------------- 密码恢复

@dataclass
class CrackConfig:
    path: str
    mode: str = "dictionary"       # dictionary / brute / mask
    wordlist: str = ""
    charset: str = "abcdefghijklmnopqrstuvwxyz0123456789"
    min_length: int = 1
    max_length: int = 6
    mask: str = "????"
    wildcard_chars: str = ""
    encoding: str = "utf-8"        # utf-8 / gbk / auto
    max_candidates: int = 0


@dataclass
class CrackResult:
    password: str | None = None
    password_bytes: bytes = b""
    tried: int = 0
    elapsed: float = 0.0
    speed: float = 0.0
    cancelled: bool = False
    error: str = ""
    entry_name: str = ""
    path: str = ""


def wildcard_charset(codes: list[str] | tuple[str, ...] | set[str]) -> str:
    """Return the union represented by selected wildcard options."""
    if "a" in codes:
        return _WILDCARD_CHARS["a"]
    chars = "".join(_WILDCARD_CHARS[code] for code in codes
                    if code in _WILDCARD_CHARS)
    return "".join(dict.fromkeys(chars))


_REMOVED_MASK_CODES = frozenset("ludhsacH")


def parse_mask(mask: str, wildcard_chars: str = "") -> list[str]:
    """解析掩码,返回每个位置的字符集。

    每个裸 ``?`` 都是通配符,字符集由界面上的多选下拉菜单决定;不再支持
    ``?l`` / ``?d`` 这类固定写法。``\\?`` 表示字面问号,其他字符按字面处理。
    """
    sets: list[str] = []
    pos = 0
    while pos < len(mask):
        ch = mask[pos]
        if ch == "\\" and pos + 1 < len(mask):
            sets.append(mask[pos + 1])
            pos += 2
            continue
        if ch == "?":
            if pos + 1 < len(mask) and mask[pos + 1] in _REMOVED_MASK_CODES:
                raise ValueError(
                    "掩码固定写法 ?l/?u/?d/?h/?H/?s/?a/?c 已移除;"
                    "请只写裸 ? 并在下拉菜单中多选字符集,字面问号用 \\?")
            sets.append(wildcard_chars or DEFAULT_WILDCARD)
            pos += 1
            continue
        sets.append(ch)
        pos += 1
    return sets


def _iter_mask(mask: str, wildcard_chars: str = "") -> Iterator[str]:
    sets = parse_mask(mask, wildcard_chars)
    if not sets or any(not chars for chars in sets):
        return
    for values in itertools.product(*sets):
        yield "".join(values)


def _count_mask(mask: str, wildcard_chars: str = "") -> int:
    sets = parse_mask(mask, wildcard_chars)
    total = 1
    for chars in sets:
        total *= max(1, len(chars))
    return total


def _iter_wordlist(path: str, encoding: str) -> Iterator[str]:
    if encoding == "auto":
        # 字典文件本身可能是 UTF-8,也可能是 Windows 下常见的 GBK;
        # 逐行尝试两种编码,避免 errors="replace" 把中文密码变成问号。
        with open(path, "rb") as f:
            for raw in f:
                raw = raw.rstrip(b"\r\n")
                text = None
                for candidate in ("utf-8", "gbk"):
                    try:
                        text = raw.decode(candidate)
                        break
                    except UnicodeDecodeError:
                        continue
                yield text if text is not None else raw.decode("utf-8", "replace")
        return
    with open(path, "r", encoding=encoding, errors="replace") as f:
        for line in f:
            yield line.rstrip("\r\n")


def _count_wordlist(path: str, encoding: str) -> int:
    with open(path, "rb") as f:
        return sum(1 for _ in f)


def _password_bytes(text: str, encoding: str) -> list[bytes]:
    if encoding == "auto":
        result = []
        for enc in ("utf-8", "gbk"):
            try:
                result.append(text.encode(enc))
            except UnicodeEncodeError:
                pass
        return result
    try:
        return [text.encode(encoding)]
    except (UnicodeEncodeError, LookupError):
        return []


def _make_crc_table() -> list[int]:
    table = []
    for value in range(256):
        crc = value
        for _ in range(8):
            crc = (crc >> 1) ^ 0xEDB88320 if crc & 1 else crc >> 1
        table.append(crc)
    return table


_CRC_TABLE = _make_crc_table()


class _ZipCryptoChecker:
    """快速 ZipCrypto 校验:先只解 12 字节头,命中后再解数据。"""

    def __init__(self, path: str, entry: zipfile.ZipInfo) -> None:
        self._header_ok = False
        self._payload = b""
        self._method = entry.compress_type
        self._crc = entry.CRC & 0xFFFFFFFF
        self._check_byte = 0
        with open(path, "rb") as f:
            f.seek(entry.header_offset)
            local = f.read(30)
            if len(local) < 30 or local[:4] != b"PK\x03\x04":
                return
            nlen = int.from_bytes(local[26:28], "little")
            elen = int.from_bytes(local[28:30], "little")
            # 带 data descriptor(bit 3)的 ZIP,本地头 CRC 可能为 0;
            # 此时 ZipCrypto 的校验字节是 DOS 修改时间的高字节,
            # 而不是中央目录 CRC 的高字节。Python zipfile 也这样判断。
            if entry.flag_bits & 0x08:
                local_time = int.from_bytes(local[10:12], "little")
                self._check_byte = (local_time >> 8) & 0xFF
            else:
                self._check_byte = (entry.CRC >> 24) & 0xFF
            f.seek(entry.header_offset + 30 + nlen + elen)
            data = f.read(entry.compress_size)
        if len(data) < 12:
            return
        self._header = data[:12]
        self._payload = data[12:]
        self._header_ok = True

    @staticmethod
    def _crc_byte(byte: int, crc: int) -> int:
        return (crc >> 8) ^ _CRC_TABLE[(crc ^ byte) & 0xFF]

    def check(self, password: bytes) -> bool:
        if not self._header_ok:
            return False
        key0, key1, key2 = 0x12345678, 0x23456789, 0x34567890
        for byte in password:
            key0 = self._crc_byte(byte, key0)
            key1 = ((key1 + (key0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
            key2 = self._crc_byte((key1 >> 24) & 0xFF, key2)

        def decrypt(data: bytes) -> bytes:
            nonlocal key0, key1, key2
            out = bytearray(len(data))
            for i, byte in enumerate(data):
                temp = (key2 | 2) & 0xFFFF
                plain = byte ^ (((temp * (temp ^ 1)) >> 8) & 0xFF)
                out[i] = plain
                key0 = self._crc_byte(plain, key0)
                key1 = ((key1 + (key0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
                key2 = self._crc_byte((key1 >> 24) & 0xFF, key2)
            return bytes(out)

        header = decrypt(self._header)
        if header[-1] != self._check_byte:
            return False
        plain = decrypt(self._payload)
        try:
            if self._method == 0:
                body = plain
            elif self._method == 8:
                body = zlib.decompress(plain, -15)
            else:
                return True
        except zlib.error:
            return False
        return (binascii.crc32(body) & 0xFFFFFFFF) == self._crc


class ZipCracker:
    """单进程 ZIP 密码恢复器。

    选择最小的加密条目做校验,避免每次解压大文件;每轮复用 ZipFile 句柄。
    """

    def __init__(self, config: CrackConfig) -> None:
        self.config = config
        self._zf: zipfile.ZipFile | None = None
        self._entry: zipfile.ZipInfo | None = None
        self._fast: _ZipCryptoChecker | None = None

    def _open(self) -> str:
        try:
            self._zf = zipfile.ZipFile(self.config.path, "r")
        except (OSError, zipfile.BadZipFile) as e:
            return f"无法打开 ZIP:{e}"
        infos = [info for info in self._zf.infolist() if info.flag_bits & 1]
        if not infos:
            self._zf.close()
            self._zf = None
            return "未发现加密条目(可能只是伪加密,请先尝试修复伪加密)"
        if all(self._has_aes(info) for info in infos):
            self._zf.close()
            self._zf = None
            return "该 ZIP 使用 AES/WinZip 加密,Python zipfile 不支持;请改用 7-Zip 或 ARCHPR"
        infos = [info for info in infos if not self._has_aes(info)]
        infos = [info for info in infos if not (info.flag_bits & 0x40)]
        if not infos:
            self._zf.close()
            self._zf = None
            return "该 ZIP 使用 Strong Encryption(bit 6),本工具只支持 ZipCrypto"
        # 0 字节条目的 CRC 恒为 0,任何能通过 1 字节头校验的密码都会“成功”,
        # 会产生假阳性;优先选择非空且确实含加密数据的条目来校验。
        verifiable = [
            info for info in infos
            if info.file_size > 0 and info.compress_size > 12
        ]
        if not verifiable:
            self._zf.close()
            self._zf = None
            return "没有可用于校验的非空加密条目(0 字节条目的 ZipCrypto 密码无法可靠验证)"
        self._entry = min(verifiable, key=lambda item: (item.file_size, item.compress_size))
        try:
            self._fast = _ZipCryptoChecker(self.config.path, self._entry)
        except OSError:
            self._fast = None
        return ""

    @staticmethod
    def _has_aes(info: zipfile.ZipInfo) -> bool:
        # WinZip AES 的标准方法是 99,通常同时带 0x9901 extra field;
        # 两者任一出现都按 AES 处理,避免误选条目。
        return info.compress_type == 99 or _has_aes_extra(info.extra)

    def _check(self, candidate: str) -> bytes | None:
        if self._zf is None or self._entry is None:
            return None
        for password in _password_bytes(candidate, self.config.encoding):
            try:
                if self._fast is not None:
                    if not self._fast.check(password):
                        continue
                # 快检通过后再走一次 zipfile,确保 CRC/解压完全正确。
                self._zf.read(self._entry, pwd=password)
                return password
            except Exception:
                # 错误密码可能表现为 RuntimeError, 也可能在 deflate 阶段
                # 抛 zlib.error / EOFError;这里都视为候选失败。
                continue
        return None

    def _total(self) -> int:
        cfg = self.config
        try:
            if cfg.mode == "dictionary":
                return _count_wordlist(cfg.wordlist, cfg.encoding)
            if cfg.mode == "mask":
                return _count_mask(cfg.mask, cfg.wildcard_chars)
            if cfg.mode == "brute":
                chars = len(cfg.charset)
                return sum(chars ** length
                           for length in range(cfg.min_length, cfg.max_length + 1))
        except (OSError, UnicodeError, ValueError):
            return 0
        return 0

    def _candidates(self) -> Iterator[str]:
        cfg = self.config
        if cfg.mode == "dictionary":
            if not cfg.wordlist:
                raise ValueError("请选择字典文件")
            yield from _iter_wordlist(cfg.wordlist, cfg.encoding)
        elif cfg.mode == "mask":
            yield from _iter_mask(cfg.mask, cfg.wildcard_chars)
        elif cfg.mode == "brute":
            if not cfg.charset:
                raise ValueError("暴力破解字符集不能为空")
            for length in range(cfg.min_length, cfg.max_length + 1):
                for values in itertools.product(cfg.charset, repeat=length):
                    yield "".join(values)
        else:
            raise ValueError(f"未知攻击模式:{cfg.mode}")

    def crack(self, progress: Callable[[int, int, float, str], None] | None = None,
              cancel: threading.Event | None = None) -> CrackResult:
        config = self.config
        start = time.monotonic()
        error = self._open()
        if error:
            return CrackResult(error=error)
        assert self._zf is not None and self._entry is not None
        total = self._total()
        tried = 0
        last_report = 0.0
        try:
            for candidate in self._candidates():
                if cancel is not None and cancel.is_set():
                    return CrackResult(tried=tried, elapsed=time.monotonic() - start,
                                       cancelled=True, entry_name=self._entry.filename)
                tried += 1
                matched = self._check(candidate)
                if matched is not None:
                    elapsed = time.monotonic() - start
                    return CrackResult(
                        password=candidate, password_bytes=matched,
                        tried=tried, elapsed=elapsed,
                        speed=tried / elapsed if elapsed else 0.0,
                        entry_name=self._entry.filename,
                    )
                if config.max_candidates and tried >= config.max_candidates:
                    break
                now = time.monotonic()
                if progress is not None and (now - last_report >= 0.15 or tried == 1):
                    last_report = now
                    elapsed = now - start
                    progress(tried, total, tried / elapsed if elapsed else 0.0, candidate)
        except (OSError, UnicodeError, ValueError) as e:
            return CrackResult(tried=tried, elapsed=time.monotonic() - start,
                               error=str(e), entry_name=self._entry.filename)
        finally:
            self._zf.close()
        elapsed = time.monotonic() - start
        return CrackResult(tried=tried, elapsed=elapsed,
                           speed=tried / elapsed if elapsed else 0.0,
                           entry_name=self._entry.filename)


def recover_zip(config: CrackConfig,
                progress: Callable[[int, int, float, str], None] | None = None,
                cancel: threading.Event | None = None) -> CrackResult:
    result = ZipCracker(config).crack(progress=progress, cancel=cancel)
    result.path = config.path
    return result


def format_duration(seconds: float) -> str:
    if seconds < 0 or seconds == float("inf"):
        return "--"
    if seconds < 60:
        return f"{seconds:.0f}s"
    minutes, sec = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h{minutes:02d}m"
    return f"{minutes}m{sec:02d}s"
