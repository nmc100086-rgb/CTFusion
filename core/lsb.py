"""图片 LSB 隐写:位平面与按位提取。

pixels 为行优先的原始像素字节(RGBA8888 时 channels=4,顺序 R,G,B,A),
channel 为通道下标(0~channels-1),bit 为位序号(0=最低位)。
"""

from __future__ import annotations


def extract_bytes(pixels: bytes, channels: int, channel: int,
                  bit: int = 0, max_bytes: int = 0) -> bytes:
    """按顺序取每个像素指定通道的第 bit 位,每 8 位拼成一个字节。"""
    out = bytearray()
    acc = 0
    count = 0
    for i in range(channel, len(pixels), channels):
        acc = (acc << 1) | ((pixels[i] >> bit) & 1)
        count += 1
        if count == 8:
            out.append(acc)
            acc = 0
            count = 0
            if max_bytes and len(out) >= max_bytes:
                break
    return bytes(out)


def bit_plane(pixels: bytes, channels: int, channel: int, bit: int = 0) -> bytes:
    """生成位平面灰度数据:该位为 1 输出 255,否则 0(长度 = 像素数)。"""
    return bytes(255 if ((pixels[i] >> bit) & 1) else 0
                 for i in range(channel, len(pixels), channels))


def preview(data: bytes, limit: int = 4000) -> str:
    """把提取结果格式化成文本预览(UTF-8 可读则直接显示,否则给 Hex)。"""
    sample = data[:limit]
    if not sample:
        return "(无数据)"
    try:
        text = sample.decode("utf-8")
        printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
        if text and printable / len(text) >= 0.85:
            suffix = "\n…(已截断)" if len(data) > limit else ""
            return f"── 文本预览 (UTF-8) ──\n{text}{suffix}"
    except UnicodeDecodeError:
        pass
    head = sample[:1024]
    suffix = "\n…" if len(data) > len(head) else ""
    return (f"── Hex 预览 ──\n{head.hex(' ')}{suffix}\n\n"
            f"共提取 {len(data):,} 字节")
