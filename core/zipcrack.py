"""ZIP 辅助:结构检查与伪加密检测/修复。

真正的密码爆破(CRC32 反查、字典)暂不在这里实现:前者需要大字典和
CPU 时间,后者依赖外部字典文件,放到 Kali 的 fcrackzip/john 更合适。
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

_MASK_SETS = {
    "l": "abcdefghijklmnopqrstuvwxyz",
    "u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "d": "0123456789",
    "h": "0123456789abcdef",
    "H": "0123456789ABCDEF",
    "s": "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
    "a": "".join(chr(i) for i in range(32, 127)),
    "c": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
}


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
    pos = cd_off
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
        entry = ZipEntry(name, flags, method, crc, csize, usize, lho, pos)
        entry.aes = bool(flags & 1) and _has_aes_extra(extra)
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


# ---------------------------------------------------------------- 密码恢复

@dataclass
class CrackConfig:
    path: str
    mode: str = "dictionary"       # dictionary / brute / mask
    wordlist: str = ""
    charset: str = "abcdefghijklmnopqrstuvwxyz0123456789"
    min_length: int = 1
    max_length: int = 6
    mask: str = "?l?l?l?l"
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


def parse_mask(mask: str) -> list[str]:
    """解析掩码,返回每个位置的字符集。

    支持 ?l ?u ?d ?h ?H ?s ?a ?c;为了兼容用户习惯,
    单独的 ? (后面不是已知代码)按字母+数字 ?c 处理。
    字面问号请写 \\?。
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
            if pos + 1 >= len(mask):
                sets.append(_MASK_SETS["c"])
                break
            code = mask[pos + 1]
            if code in _MASK_SETS:
                sets.append(_MASK_SETS[code])
                pos += 2
            else:
                # qctf2026???? 这类写法:每个 ? 当字母+数字通配。
                sets.append(_MASK_SETS["c"])
                pos += 1
            continue
        sets.append(ch)
        pos += 1
    return sets


def _iter_mask(mask: str) -> Iterator[str]:
    sets = parse_mask(mask)
    if not sets or any(not chars for chars in sets):
        return
    for values in itertools.product(*sets):
        yield "".join(values)


def _count_mask(mask: str) -> int:
    sets = parse_mask(mask)
    total = 1
    for chars in sets:
        total *= max(1, len(chars))
    return total


def _file_encoding(encoding: str) -> str:
    return "utf-8" if encoding == "auto" else encoding


def _iter_wordlist(path: str, encoding: str) -> Iterator[str]:
    with open(path, "r", encoding=_file_encoding(encoding), errors="replace") as f:
        for line in f:
            yield line.rstrip("\r\n")


def _count_wordlist(path: str, encoding: str) -> int:
    count = 0
    with open(path, "r", encoding=_file_encoding(encoding), errors="replace") as f:
        for _ in f:
            count += 1
    return count


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
        with open(path, "rb") as f:
            f.seek(entry.header_offset)
            local = f.read(30)
            if len(local) < 30 or local[:4] != b"PK\x03\x04":
                return
            nlen = int.from_bytes(local[26:28], "little")
            elen = int.from_bytes(local[28:30], "little")
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
        if header[-1] != ((self._crc >> 24) & 0xFF):
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
        self._entry = min(infos, key=lambda item: (item.file_size, item.compress_size))
        try:
            self._fast = _ZipCryptoChecker(self.config.path, self._entry)
        except OSError:
            self._fast = None
        return ""

    @staticmethod
    def _has_aes(info: zipfile.ZipInfo) -> bool:
        return _has_aes_extra(info.extra)

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
                return _count_mask(cfg.mask)
            if cfg.mode == "brute":
                chars = len(cfg.charset)
                return sum(chars ** length
                           for length in range(cfg.min_length, cfg.max_length + 1))
        except (OSError, UnicodeError):
            return 0
        return 0

    def _candidates(self) -> Iterator[str]:
        cfg = self.config
        if cfg.mode == "dictionary":
            if not cfg.wordlist:
                raise ValueError("请选择字典文件")
            yield from _iter_wordlist(cfg.wordlist, cfg.encoding)
        elif cfg.mode == "mask":
            yield from _iter_mask(cfg.mask)
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
