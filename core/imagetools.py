"""轻量图像工具:通道拆分、反色、XOR、差分与直方图。"""

from __future__ import annotations

from PySide6.QtGui import QImage


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


def xor_images(left: QImage, right: QImage) -> QImage | None:
    if left.size() != right.size():
        return None
    a, width, height = _rgba(left)
    b, _, _ = _rgba(right)
    return _from_rgba(bytes(x ^ y for x, y in zip(a, b)), width, height)


def difference(left: QImage, right: QImage) -> QImage | None:
    if left.size() != right.size():
        return None
    a, width, height = _rgba(left)
    b, _, _ = _rgba(right)
    return _from_rgba(bytes(abs(x - y) for x, y in zip(a, b)), width, height)


def histogram(image: QImage) -> list[int]:
    counts = [0] * 256
    raw, _, _ = _rgba(image)
    for i in range(0, len(raw), 4):
        for ch in range(3):
            counts[raw[i + ch]] += 1
    return counts
