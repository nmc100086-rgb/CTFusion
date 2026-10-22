"""ZIP 辅助:结构检查与伪加密检测/修复。

真正的密码爆破(CRC32 反查、字典)暂不在这里实现:前者需要大字典和
CPU 时间,后者依赖外部字典文件,放到 Kali 的 fcrackzip/john 更合适。
"""

from __future__ import annotations

import binascii
import zlib
from dataclasses import dataclass, field

from core import fileparse

_LOCAL = b"PK\x03\x04"
_CENTRAL = b"PK\x01\x02"


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
        entry = ZipEntry(name, flags, method, crc, csize, usize, lho, pos)
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
