"""文件二进制分析:哈希、熵、可打印字符串、光标处数据解释。"""

from __future__ import annotations

import hashlib
import math
import re
import struct
from datetime import datetime, timezone


def digests(data: bytes) -> dict[str, str]:
    """常见哈希:MD5 / SHA1 / SHA256 / CRC32。"""
    import zlib

    return {
        "MD5": hashlib.md5(data).hexdigest(),
        "SHA1": hashlib.sha1(data).hexdigest(),
        "SHA256": hashlib.sha256(data).hexdigest(),
        "CRC32": f"{zlib.crc32(data) & 0xFFFFFFFF:08X}",
    }


def entropy(data: bytes) -> float:
    """香农熵(bit/byte),0 表示全相同,8 表示完全随机。"""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    result = 0.0
    for c in counts:
        if c:
            p = c / total
            result -= p * math.log2(p)
    return result


def entropy_blocks(data: bytes, block: int = 1024) -> list[float]:
    """按块计算熵,用于绘制熵图。"""
    if not data:
        return []
    # 块太大时自动放大块尺寸,保证样本数不超过 2048
    while len(data) // block > 2048:
        block *= 2
    return [entropy(data[i:i + block]) for i in range(0, len(data), block)]


def byte_histogram(data: bytes) -> list[int]:
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return counts


def strings(data: bytes, min_len: int = 4, pattern: str = "",
            limit: int = 0) -> list[tuple[int, str]]:
    """提取连续可打印字符串(等价 strings 命令),pattern 为正则过滤。"""
    if min_len < 1:
        min_len = 1
    rx = re.compile(pattern) if pattern else None
    out: list[tuple[int, str]] = []
    buf = bytearray()
    start = 0
    for i, b in enumerate(data):
        if 32 <= b <= 126 or b == 9:
            if not buf:
                start = i
            buf.append(b)
        else:
            if len(buf) >= min_len:
                _push(out, bytes(buf), start, rx)
                if limit and len(out) >= limit:
                    return out
            buf = bytearray()
    if len(buf) >= min_len:
        _push(out, bytes(buf), start, rx)
    return out


def _push(out: list[tuple[int, str]], raw: bytes, start: int, rx: re.Pattern | None) -> None:
    text = raw.decode("ascii", "replace")
    if rx is not None and not rx.search(text):
        return
    out.append((start, text))


def interpret_at(data: bytes, offset: int) -> list[tuple[str, str]]:
    """解释 offset 处的字节,给出多种数据类型的取值。"""
    if not 0 <= offset < len(data):
        return []
    chunk = data[offset:offset + 8]
    rows: list[tuple[str, str]] = [("字节", f"0x{chunk[0]:02X} ({chunk[0]})")]

    for name, fmt, size in (
        ("uint8", "<B", 1), ("int8", "<b", 1),
        ("uint16 LE", "<H", 2), ("uint16 BE", ">H", 2),
        ("int16 LE", "<h", 2), ("int16 BE", ">h", 2),
        ("uint32 LE", "<I", 4), ("uint32 BE", ">I", 4),
        ("int32 LE", "<i", 4), ("int32 BE", ">i", 4),
        ("uint64 LE", "<Q", 8), ("uint64 BE", ">Q", 8),
    ):
        if len(chunk) >= size:
            try:
                value = struct.unpack(fmt, chunk[:size])[0]
            except struct.error:
                continue
            rows.append((name, str(value)))

    if len(chunk) >= 4:
        try:
            rows.append(("float LE", f"{struct.unpack('<f', chunk[:4])[0]:.6g}"))
            rows.append(("float BE", f"{struct.unpack('>f', chunk[:4])[0]:.6g}"))
        except struct.error:
            pass
    if len(chunk) >= 8:
        try:
            rows.append(("double LE", f"{struct.unpack('<d', chunk)[0]:.6g}"))
        except struct.error:
            pass

    ts = int.from_bytes(chunk[:4], "little")
    if 0 < ts < 4102444800:  # 1970 ~ 2100 之间才当作时间戳
        rows.append(("时间戳 LE", datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")))
    ts_be = int.from_bytes(chunk[:4], "big")
    if 0 < ts_be < 4102444800:
        rows.append(("时间戳 BE", datetime.fromtimestamp(ts_be, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")))

    text = data[offset:offset + 32]
    rows.append(("ASCII", "".join(chr(b) if 32 <= b <= 126 else "." for b in text)))
    rows.append(("UTF-8 尝试", text.decode("utf-8", "replace").replace("\ufffd", "·")))
    return rows
