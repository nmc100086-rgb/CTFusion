"""StegSolve 风格的多 bit / 多通道数据提取。"""

from __future__ import annotations


def extract_selected(pixels: bytes, channels: int,
                     selected: dict[int, set[int]],
                     channel_order: tuple[int, ...] | list[int],
                     bit_order: str = "msb",
                     plane_order: str = "low",
                     max_bytes: int = 0) -> bytes:
    """按像素 -> 通道 -> bit 平面顺序提取位流并打包。

    selected 形如 {0: {0, 1}, 1: {0}};plane_order="low" 表示每个通道
    从低位到高位, "high" 则相反。
    """
    if channels <= 0:
        return b""
    order = [ch for ch in channel_order if 0 <= ch < channels]
    if not order:
        return b""
    selected_bits: dict[int, list[int]] = {}
    for ch in order:
        bits = sorted(bit for bit in selected.get(ch, set()) if 0 <= bit <= 7)
        if plane_order == "high":
            bits.reverse()
        selected_bits[ch] = bits
    if not any(selected_bits.values()):
        return b""
    total_pixels = len(pixels) // channels
    out = bytearray()
    acc = 0
    count = 0
    for pixel in range(total_pixels):
        base = pixel * channels
        for ch in order:
            value = pixels[base + ch]
            for bit in selected_bits[ch]:
                current = (value >> bit) & 1
                if bit_order == "lsb":
                    acc |= current << count
                else:
                    acc = (acc << 1) | current
                count += 1
                if count == 8:
                    out.append(acc)
                    acc = 0
                    count = 0
                    if max_bytes and len(out) >= max_bytes:
                        return bytes(out)
    return bytes(out)
