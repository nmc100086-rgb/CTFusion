"""轻量图像工具:通道拆分、反色、XOR、差分与直方图。"""

from __future__ import annotations

import random

from PySide6.QtCore import Qt
from PySide6.QtGui import QImage


def rgba_data(image: QImage) -> tuple[bytes, int, int]:
    return _rgba(image)


def _rgba(image: QImage) -> tuple[bytes, int, int]:
    rgba = image.convertToFormat(QImage.Format_RGBA8888)
    raw = bytes(rgba.constBits())
    stride = rgba.bytesPerLine()
    width, height = rgba.width(), rgba.height()
    row = width * 4
    if stride == row:
        return raw[:row * height], width, height
    return b"".join(raw[y * stride:y * stride + row] for y in range(height)), width, height


def _from_rgba(raw: bytes, width: int, height: int) -> QImage:
    return QImage(raw, width, height, width * 4, QImage.Format_RGBA8888).copy()


def channel_image(image: QImage, channel: int) -> QImage:
    raw, width, height = _rgba(image)
    plane = bytes(raw[i] for i in range(channel, len(raw), 4))
    return QImage(plane, width, height, width, QImage.Format_Grayscale8).copy()


def invert(image: QImage) -> QImage:
    raw, width, height = _rgba(image)
    out = bytearray(raw)
    for i in range(0, len(out), 4):
        out[i] = 255 - out[i]
        out[i + 1] = 255 - out[i + 1]
        out[i + 2] = 255 - out[i + 2]
    return _from_rgba(bytes(out), width, height)


def combine(left: QImage, right: QImage, operation: str = "xor") -> QImage | None:
    """StegSolve Image Combiner 的常用运算(RGB 运算,保留左图 alpha)。"""
    if left.size() != right.size():
        return None
    a, width, height = _rgba(left)
    b, _, _ = _rgba(right)
    if operation not in {"xor", "add", "sub", "and", "or", "min", "max", "diff"}:
        return None
    functions = {
        "xor": lambda x, y: x ^ y,
        "add": lambda x, y: min(255, x + y),
        "sub": lambda x, y: max(0, x - y),
        "and": lambda x, y: x & y,
        "or": lambda x, y: x | y,
        "min": min,
        "max": max,
        "diff": lambda x, y: abs(x - y),
    }
    func = functions[operation]
    out = bytearray(len(a))
    for i in range(0, len(a), 4):
        out[i] = func(a[i], b[i])
        out[i + 1] = func(a[i + 1], b[i + 1])
        out[i + 2] = func(a[i + 2], b[i + 2])
        out[i + 3] = a[i + 3]
    return _from_rgba(bytes(out), width, height)


def xor_images(left: QImage, right: QImage) -> QImage | None:
    return combine(left, right, "xor")


def difference(left: QImage, right: QImage) -> QImage | None:
    return combine(left, right, "diff")


def random_color_map(image: QImage, seed: int = 0) -> QImage:
    """把每种 RGB 颜色映射成随机颜色,常用于打乱调色板寻找轮廓。"""
    raw, width, height = _rgba(image)
    rng = random.Random(seed)
    mapping: dict[tuple[int, int, int], tuple[int, int, int]] = {}
    out = bytearray(len(raw))
    for i in range(0, len(raw), 4):
        key = (raw[i], raw[i + 1], raw[i + 2])
        color = mapping.get(key)
        if color is None:
            color = (rng.randrange(256), rng.randrange(256), rng.randrange(256))
            mapping[key] = color
        out[i], out[i + 1], out[i + 2], out[i + 3] = (
            color[0], color[1], color[2], raw[i + 3])
    return _from_rgba(bytes(out), width, height)


def stereogram(image: QImage, min_offset: int = 5, max_offset: int = 60) -> QImage | None:
    """简易 autostereogram 深度图:寻找左右像素最相似的横向偏移。"""
    if image.width() < 4 or image.height() < 1:
        return None
    # 限制计算量,过大图像先缩小。
    scaled = image
    if image.width() * image.height() > 300_000:
        scaled = image.scaled(500, 500, Qt.KeepAspectRatio,
                              Qt.SmoothTransformation)
    raw, width, height = _rgba(scaled)
    min_offset = max(1, min(min_offset, width - 1))
    max_offset = max(min_offset, min(max_offset, width - 1))
    out = bytearray(width * height)
    for y in range(height):
        row = y * width
        for x in range(width):
            if x < max_offset:
                continue
            best_offset = min_offset
            best_diff = 1 << 30
            for offset in range(min_offset, max_offset + 1):
                p1 = (row + x) * 4
                p2 = (row + x - offset) * 4
                diff = (abs(raw[p1] - raw[p2])
                        + abs(raw[p1 + 1] - raw[p2 + 1])
                        + abs(raw[p1 + 2] - raw[p2 + 2]))
                if diff < best_diff:
                    best_diff = diff
                    best_offset = offset
            value = int((best_offset - min_offset) * 255 / max(1, max_offset - min_offset))
            out[row + x] = max(0, min(255, value))
    return QImage(bytes(out), width, height, width, QImage.Format_Grayscale8).copy()


def histogram(image: QImage) -> list[int]:
    counts = [0] * 256
    raw, _, _ = _rgba(image)
    for i in range(0, len(raw), 4):
        for ch in range(3):
            counts[raw[i + ch]] += 1
    return counts
