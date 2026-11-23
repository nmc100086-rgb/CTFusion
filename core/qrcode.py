"""二维码 / 条码识别（zxing-cpp 的薄封装）。

支持二维码、Micro QR、Data Matrix、Aztec、PDF417 以及常见一维条码。
输入为图片文件字节；识别结果保留原始字节，便于复制真正的内容而不是
经过转码后的近似文本。
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from pathlib import Path

try:  # 打包时 PyInstaller 会收集 zxingcpp 的扩展模块
    import zxingcpp
except Exception as _exc:  # pragma: no cover - 只在依赖缺失时触发
    zxingcpp = None  # type: ignore[assignment]
    _IMPORT_ERROR = str(_exc)
else:
    _IMPORT_ERROR = ""

try:
    from PIL import Image, UnidentifiedImageError
except Exception as _exc:  # pragma: no cover
    Image = None  # type: ignore[assignment]
    UnidentifiedImageError = Exception  # type: ignore[assignment,misc]
    _PIL_ERROR = str(_exc)
else:
    _PIL_ERROR = ""

MAX_IMAGE_PIXELS = 120_000_000
MAX_IMAGE_BYTES = 128 * 1024 * 1024


class QrError(ValueError):
    """识别失败，message 可直接展示给用户。"""


@dataclass(frozen=True)
class BarcodeResult:
    text: str
    raw: bytes
    format: str
    content_type: str = ""
    ec_level: str = ""
    orientation: int = 0
    position: str = ""
    valid: bool = True

    @property
    def raw_hex(self) -> str:
        return self.raw.hex(" ").upper()

    @property
    def is_empty(self) -> bool:
        return not self.text and not self.raw


def available() -> bool:
    return zxingcpp is not None and Image is not None


def dependency_error() -> str:
    if zxingcpp is None:
        return f"缺少二维码识别组件 zxing-cpp:{_IMPORT_ERROR}"
    if Image is None:
        return f"缺少图片解码组件 Pillow:{_PIL_ERROR}"
    return ""


def _to_text(result) -> str:
    text = getattr(result, "text", "") or ""
    if text:
        return text
    raw = getattr(result, "bytes", b"") or b""
    if not raw:
        return ""
    # 某些二进制 QR 没有文本表示；尽量给出可读形式，复制原始字节仍可用。
    for encoding in ("utf-8", "gb18030", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def scan_image_bytes(data: bytes) -> list[BarcodeResult]:
    """识别图片字节中的二维码/条码。"""
    if not data:
        raise QrError("图片为空")
    if len(data) > MAX_IMAGE_BYTES:
        raise QrError(
            f"图片文件过大({len(data) / 1024 / 1024:.1f} MB)，"
            f"上限为 {MAX_IMAGE_BYTES // 1024 // 1024} MB")
    if not available():
        raise QrError(dependency_error())
    try:
        image = Image.open(io.BytesIO(data))
        # 先检查尺寸再完整解码，避免像素炸弹。
        width, height = image.size
        if width <= 0 or height <= 0:
            raise QrError("图片尺寸无效")
        if width * height > MAX_IMAGE_PIXELS:
            raise QrError(
                f"图片像素数过大({width} × {height})，"
                f"上限为 {MAX_IMAGE_PIXELS // 1_000_000} 百万像素")
        image.seek(0)
        image = image.convert("RGB")
    except QrError:
        raise
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise QrError(f"无法解析图片:{exc}") from exc

    try:
        found = zxingcpp.read_barcodes(
            image,
            try_rotate=True,
            try_downscale=True,
            try_invert=True,
            return_errors=False,
        )
    except Exception as exc:  # pragma: no cover - 第三方库异常兜底
        raise QrError(f"二维码识别失败:{exc}") from exc

    results: list[BarcodeResult] = []
    for item in found:
        raw = bytes(getattr(item, "bytes", b"") or b"")
        text = _to_text(item)
        valid = bool(getattr(item, "valid", True))
        if not valid:
            continue
        results.append(BarcodeResult(
            text=text,
            raw=raw,
            format=str(getattr(item, "format", "") or "未知"),
            content_type=str(getattr(item, "content_type", "") or ""),
            ec_level=str(getattr(item, "ec_level", "") or ""),
            orientation=int(getattr(item, "orientation", 0) or 0),
            position=str(getattr(item, "position", "") or ""),
            valid=valid,
        ))
    return results


def scan_image_file(path: str | Path) -> list[BarcodeResult]:
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise QrError(f"读取图片失败:{exc}") from exc
    return scan_image_bytes(data)


def self_test() -> tuple[bool, str]:
    """打包自检：生成一个二维码并立刻识别。"""
    if not available():
        return False, dependency_error()
    try:
        barcode = zxingcpp.create_barcode(
            "flag{qr_self_test}", zxingcpp.BarcodeFormat.QRCode)
        image = barcode.to_image(scale=4)
        width, height = image.shape
        pil = Image.frombytes("L", (width, height), bytes(memoryview(image)))
        buffer = io.BytesIO()
        pil.save(buffer, "PNG")
        found = scan_image_bytes(buffer.getvalue())
    except Exception as exc:
        return False, f"二维码自检异常:{exc}"
    if not found or found[0].text != "flag{qr_self_test}":
        return False, "二维码自检未能还原原始内容"
    return True, "QR OK"
