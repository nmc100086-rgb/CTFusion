"""WAV 元信息与采样 LSB 提取(不依赖 numpy/scipy)。"""

from __future__ import annotations

import io
import wave
from dataclasses import dataclass

from core import lsb


@dataclass
class WavInfo:
    channels: int
    sample_width: int
    frame_rate: int
    frames: int
    duration: float


def read_info(data: bytes) -> WavInfo | None:
    try:
        with wave.open(io.BytesIO(data), "rb") as wav:
            frames = wav.getnframes()
            rate = wav.getframerate()
            return WavInfo(
                wav.getnchannels(), wav.getsampwidth(), rate,
                frames, frames / rate if rate else 0.0,
            )
    except (wave.Error, EOFError, OSError, ValueError):
        return None


def extract_lsb(data: bytes, channel: int = 0, bit: int = 0,
                bit_order: str = "msb", max_bytes: int = 0,
                channels_sel: tuple[int, ...] | list[int] | None = None) -> bytes:
    """从 WAV PCM 采样中提取指定位,按 8 bit 拼字节。"""
    try:
        with wave.open(io.BytesIO(data), "rb") as wav:
            channels = wav.getnchannels()
            width = wav.getsampwidth()
            frames = wav.readframes(wav.getnframes())
    except (wave.Error, EOFError, OSError, ValueError):
        return b""
    if width not in (1, 2, 3, 4) or channels <= 0:
        return b""
    if channels_sel is None:
        channels_sel = (channel,)
    use = [item for item in channels_sel if 0 <= item < channels]
    if not use or not 0 <= bit < width * 8:
        return b""
    out = bytearray()
    acc = 0
    count = 0
    for frame in range(len(frames) // (width * channels)):
        base = frame * width * channels
        for ch in use:
            start = base + ch * width
            value = int.from_bytes(frames[start:start + width], "little")
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


def preview(data: bytes, encoding: str = "auto", limit: int = 4000) -> str:
    return lsb.preview(data, limit=limit, encoding=encoding)
