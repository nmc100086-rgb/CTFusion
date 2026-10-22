"""图片 LSB 隐写:位平面与按位提取。

pixels 为行优先的原始像素字节(RGBA8888 时 channels=4,顺序 R,G,B,A),
channel 为通道下标(0~channels-1),bit 为位序号(0=最低位)。

extract_bytes 支持:
- MSB-first / LSB-first 两种位打包顺序;
- 多通道组合;
- 起始像素和像素步长。
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass

_FLAG_RE = re.compile(r"\b(?:flag|ctf|key)\s*\{[^}\n]{0,300}\}", re.IGNORECASE)


def _normalise_channels(channels: int, channel: int,
                        channels_sel: tuple[int, ...] | list[int] | None) -> list[int]:
    if channels <= 0:
        return []
    raw = tuple(channels_sel) if channels_sel is not None else (channel,)
    result: list[int] = []
    for item in raw:
        if 0 <= item < channels and item not in result:
            result.append(item)
    return result


def extract_bytes(pixels: bytes, channels: int, channel: int,
                  bit: int = 0, max_bytes: int = 0, *,
                  bit_order: str = "msb",
                  start_pixel: int = 0,
                  pixel_step: int = 1,
                  channels_sel: tuple[int, ...] | list[int] | None = None) -> bytes:
    """按顺序取每个像素指定通道的第 bit 位,每 8 位拼成一个字节。

    bit_order="msb" 时第一个 bit 是字节最高位;"lsb" 时第一个 bit 是最低位。
    """
    if not 0 <= bit <= 7:
        return b""
    use_channels = _normalise_channels(channels, channel, channels_sel)
    if not use_channels:
        return b""
    total_pixels = len(pixels) // channels
    start = max(0, min(int(start_pixel), total_pixels))
    step = max(1, int(pixel_step))
    out = bytearray()
    acc = 0
    count = 0
    for pixel in range(start, total_pixels, step):
        base = pixel * channels
        for ch in use_channels:
            value = (pixels[base + ch] >> bit) & 1
            if bit_order == "lsb":
                acc |= value << count
            else:
                acc = (acc << 1) | value
            count += 1
            if count == 8:
                out.append(acc)
                acc = 0
                count = 0
                if max_bytes and len(out) >= max_bytes:
                    return bytes(out)
    return bytes(out)


def bit_plane(pixels: bytes, channels: int, channel: int, bit: int = 0) -> bytes:
    """生成位平面灰度数据:该位为 1 输出 255,否则 0(长度 = 像素数)。"""
    return bytes(255 if ((pixels[i] >> bit) & 1) else 0
                 for i in range(channel, len(pixels), channels))


def _decode_text(sample: bytes, encoding: str) -> tuple[str, str] | None:
    candidates: list[tuple[str, str]] = []
    if encoding and encoding != "auto":
        candidates.append((encoding, encoding))
    else:
        candidates.append(("UTF-8", "utf-8-sig"))
        if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
            candidates.append(("UTF-16", "utf-16"))
        candidates.extend([
            ("GB18030", "gb18030"),
            ("UTF-16 LE", "utf-16-le"),
            ("UTF-16 BE", "utf-16-be"),
            ("Latin-1", "latin-1"),
        ])
    for label, codec in candidates:
        try:
            text = sample.decode(codec)
        except (UnicodeDecodeError, LookupError):
            continue
        if not text or "\x00" in text:
            continue
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in text):
            continue
        if (not encoding or encoding == "auto") and codec in ("utf-16-le", "utf-16-be"):
            zero_ratio = sample.count(0) / max(1, len(sample))
            cjk_ratio = sum("\u4e00" <= ch <= "\u9fff" for ch in text) / len(text)
            if zero_ratio < 0.15 and cjk_ratio < 0.5:
                continue
        printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
        if printable / len(text) >= 0.85:
            return label, text
    return None


def preview(data: bytes, limit: int = 4000, encoding: str = "auto") -> str:
    """把提取结果格式化成文本预览,否则给 Hex。

    encoding 为 auto 时依次尝试 UTF-8 / UTF-16 / GB18030 / Latin-1。
    """
    sample = data[:limit]
    if not sample:
        return "(无数据)"
    decoded = _decode_text(sample, encoding)
    if decoded is not None:
        label, text = decoded
        suffix = "\n…(已截断)" if len(data) > limit else ""
        return f"── 文本预览 ({label}) ──\n{text}{suffix}"
    head = sample[:1024]
    suffix = "\n…" if len(data) > len(head) else ""
    return (f"── Hex 预览 ──\n{head.hex(' ')}{suffix}\n\n"
            f"共提取 {len(data):,} 字节")


@dataclass(frozen=True)
class RowScan:
    """一种通道顺序/行的 LSB 文本扫描结果。"""

    label: str
    text: str
    score: float
    has_flag: bool
    offset: int = 0


def channel_orders(channels: int, max_channels: int = 4) -> list[tuple[int, ...]]:
    """返回通道顺序排列;16-bit 的 8 个字节通道只取前 4 个避免 40320 种组合。

    同时包含单通道、三通道和四通道组合:截图里的 RGB/BRG 属于三通道,
    只藏在 R 通道的数据则靠单通道行发现。
    """
    if channels <= 0:
        return []
    use = min(channels, max_channels)
    orders: list[tuple[int, ...]] = [(i,) for i in range(use)]
    if use >= 3:
        orders.extend(itertools.permutations(range(use), 3))
    if use >= 2:
        orders.extend(itertools.permutations(range(use), use))
    seen: set[tuple[int, ...]] = set()
    result: list[tuple[int, ...]] = []
    for order in orders:
        if order not in seen:
            seen.add(order)
            result.append(order)
    return result


def _readable(raw: bytes) -> str:
    return "".join(chr(b) if 32 <= b <= 126 or b in (9, 10, 13) else "." for b in raw)


def _score_text(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    score = printable / len(text)
    if _FLAG_RE.search(text):
        score += 2.0
    return score


def scan_orders(pixels: bytes, channels: int, names: tuple[str, ...],
                bit: int = 0, bit_order: str = "msb",
                max_bytes: int = 256, rows: bool = False,
                width: int = 0, max_results: int = 800) -> list[RowScan]:
    """按所有通道排列提取 LSB,返回可直接展示的文本行。

    rows=False 时每个通道顺序输出整图一段;rows=True 时逐行扫描并只保留
    含 flag 或可打印比例较高的行,适合寻找“藏在某一行”的数据。
    """
    orders = channel_orders(channels)
    if not orders:
        return []
    labels = tuple(names[index] if index < len(names) else str(index)
                   for index in range(min(channels, 4)))
    results: list[RowScan] = []

    def add(label: str, raw: bytes, offset: int) -> None:
        text = _readable(raw)
        score = _score_text(text)
        results.append(RowScan(label, text, score, bool(_FLAG_RE.search(text)), offset))

    if not rows:
        for order in orders:
            label = "".join(labels[i] for i in order)
            raw = extract_bytes(
                pixels, channels, order[0], bit, max_bytes,
                bit_order=bit_order, channels_sel=order,
            )
            add(label, raw, 0)
    else:
        if width <= 0:
            return []
        total_pixels = len(pixels) // channels
        height = total_pixels // width
        for order in orders:
            label = "".join(labels[i] for i in order)
            for y in range(height):
                start = y * width * channels
                end = start + width * channels
                raw = extract_bytes(
                    pixels[start:end], channels, order[0], bit, max_bytes,
                    bit_order=bit_order, channels_sel=order,
                )
                text = _readable(raw)
                score = _score_text(text)
                if _FLAG_RE.search(text) or score >= 0.85:
                    results.append(RowScan(
                        f"{label} row {y + 1}", text, score,
                        bool(_FLAG_RE.search(text)), start // channels,
                    ))
                if len(results) >= max_results:
                    return _rank(results)
    return _rank(results)


def _rank(results: list[RowScan]) -> list[RowScan]:
    """flag 行优先,其次按可打印评分和标签排序。"""
    return sorted(results, key=lambda item: (not item.has_flag, -item.score, item.label))
