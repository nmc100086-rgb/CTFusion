"""Base64 / Hex 与文件数据互转。

面向 CTF 杂项里的常见操作：
- Base64 字符串 -> PNG/JPEG/GIF 图片
- Hex 字符串 -> ZIP/RAR/PDF/PE 等任意文件
- 文件 -> Base64 / Hex

这里刻意不把“Base64 解码成文本”混进来：纯文本解码仍由编码解码页的
Base64 算法负责；本模块只处理需要落盘/预览的二进制数据。
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from pathlib import Path

from core.filetype import IdentifyResult, identify

MAX_ENCODED_CHARS = 128 * 1024 * 1024
MAX_DECODED_BYTES = 128 * 1024 * 1024

_IMAGE_KINDS = {
    "PNG", "JPEG", "GIF", "BMP", "WEBP", "TIFF", "ICO", "PSD",
}
_TEXT_KINDS = {"文本"}


class DataToolError(ValueError):
    """数据转换失败，message 可直接展示给用户。"""


@dataclass
class DecodedPayload:
    data: bytes
    method: str
    detected: IdentifyResult
    default_name: str = "decoded.bin"
    warnings: list[str] = field(default_factory=list)

    @property
    def kind(self) -> str:
        return self.detected.real_name

    @property
    def is_image(self) -> bool:
        return self.detected.real_name in _IMAGE_KINDS

    @property
    def is_zip(self) -> bool:
        return self.detected.real_name == "ZIP"

    @property
    def is_text(self) -> bool:
        return self.detected.real_name in _TEXT_KINDS

    @property
    def extension(self) -> str:
        if self.detected.real_ext:
            return self.detected.real_ext
        return ".bin"


def _clean_base64(text: str) -> str:
    # 允许换行、空格；去掉常见 data URI 前缀。
    text = text.strip()
    if text.lower().startswith("data:"):
        comma = text.find(",")
        if comma < 0:
            raise DataToolError("Data URI 缺少逗号分隔符")
        header, text = text[:comma], text[comma + 1:]
        if ";base64" not in header.lower():
            raise DataToolError("Data URI 不是 base64 形式")
    return re.sub(r"\s+", "", text)


def decode_base64(text: str) -> bytes:
    cleaned = _clean_base64(text)
    if not cleaned:
        raise DataToolError("Base64 输入为空")
    if len(cleaned) > MAX_ENCODED_CHARS:
        raise DataToolError("Base64 输入过长")
    # URL-safe 变体在 CTF 中很常见；先按标准表解码，失败再替换字符。
    candidates = [cleaned]
    if "-" in cleaned or "_" in cleaned:
        candidates.append(cleaned.replace("-", "+").replace("_", "/"))
    for candidate in candidates:
        padded = candidate + "=" * (-len(candidate) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(raw) > MAX_DECODED_BYTES:
            raise DataToolError("解码结果过大")
        return raw
    raise DataToolError(
        "不是合法的 Base64。请检查是否包含非 Base64 字符，"
        "或改用 Hex 模式。")


def _normalize_hex(text: str) -> str:
    cleaned = text.strip()
    cleaned = re.sub(r"0[xX]", "", cleaned)
    cleaned = cleaned.replace("\\x", "").replace("\\X", "")
    # 允许空格、逗号、冒号、分号、下划线和短横线作为分隔符。
    cleaned = re.sub(r"[\s,;:_-]+", "", cleaned)
    return cleaned


def decode_hex(text: str) -> bytes:
    cleaned = _normalize_hex(text)
    if not cleaned:
        raise DataToolError("Hex 输入为空")
    if len(cleaned) > MAX_ENCODED_CHARS * 2:
        raise DataToolError("Hex 输入过长")
    if not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        raise DataToolError("Hex 中包含非十六进制字符（允许 0x 前缀和空格分隔）")
    if len(cleaned) % 2:
        raise DataToolError("Hex 长度必须是偶数；每个字节需要两位十六进制数")
    raw = bytes.fromhex(cleaned)
    if len(raw) > MAX_DECODED_BYTES:
        raise DataToolError("解码结果过大")
    return raw


def _looks_like_hex(text: str) -> bool:
    cleaned = _normalize_hex(text)
    if not cleaned or len(cleaned) % 2:
        return False
    if not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        return False
    original = text.strip()
    # 有明确分隔符/前缀时优先按 Hex 解释；纯字母数字串再让 magic 决定。
    return bool(
        re.search(r"0[xX]", original)
        or re.search(r"\\[xX]", original)
        or re.search(r"[\s,;:_-]", original)
        or len(cleaned) >= 2
    )


def _looks_like_base64(text: str) -> bool:
    cleaned = _clean_base64(text)
    if len(cleaned) < 4:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", cleaned):
        return False
    return len(cleaned) % 4 == 0 or cleaned.endswith("=")


def _detect(data: bytes, name: str = "") -> IdentifyResult:
    result = identify(data, name)
    if result.real_name == "未知" and data:
        # 没有 magic 时，明确区分“可读文本”和普通二进制。
        try:
            text = data[:4096].decode("utf-8")
        except UnicodeDecodeError:
            pass
        else:
            printable = sum(
                1 for c in text if c.isprintable() or c in "\n\r\t")
            if text and printable / len(text) >= 0.95:
                result.real_name = "文本"
                result.real_ext = ".txt"
    return result


def _default_name(result: IdentifyResult, method: str) -> str:
    ext = result.real_ext or ".bin"
    stem = "decoded_base64" if method == "Base64" else "decoded_hex"
    return f"{stem}{ext}"


def _recognized_score(result: IdentifyResult) -> int:
    name = result.real_name
    if name in _IMAGE_KINDS or name == "ZIP":
        return 30
    if name in ("PDF", "RAR", "7Z", "GZIP", "PE", "ELF", "WAV", "MP4"):
        return 20
    if name not in ("未知", "文本"):
        return 10
    if name == "文本":
        return 3
    return 0


def decode_payload(text: str, mode: str = "auto", name_hint: str = "") -> DecodedPayload:
    """把 Base64/Hex 文本解码为二进制，并识别真实文件类型。

    mode: ``auto`` / ``base64`` / ``hex``
    """
    if not text or not text.strip():
        raise DataToolError("请先粘贴 Base64 或 Hex 内容")
    if len(text) > MAX_ENCODED_CHARS:
        raise DataToolError("输入内容过长")

    warnings: list[str] = []
    mode = (mode or "auto").lower()
    if mode not in ("auto", "base64", "hex"):
        raise DataToolError(f"未知的解码方式:{mode}")

    if mode == "base64":
        data = decode_base64(text)
        method = "Base64"
    elif mode == "hex":
        data = decode_hex(text)
        method = "Hex"
    else:
        hex_ok = _looks_like_hex(text)
        b64_ok = _looks_like_base64(text)
        if not hex_ok and not b64_ok:
            raise DataToolError(
                "无法自动判断是 Base64 还是 Hex。请手动选择格式。")
        options: list[tuple[int, str, bytes, IdentifyResult]] = []
        if hex_ok:
            try:
                raw = decode_hex(text)
            except DataToolError:
                pass
            else:
                result = _detect(raw, name_hint)
                options.append((_recognized_score(result), "Hex", raw, result))
        if b64_ok:
            try:
                raw = decode_base64(text)
            except DataToolError:
                pass
            else:
                result = _detect(raw, name_hint)
                options.append((_recognized_score(result), "Base64", raw, result))
        if not options:
            raise DataToolError(
                "输入既不能按 Base64 解码，也不能按 Hex 解码。")
        # magic 识别优先；都识别不出时，明确带 0x/空格分隔的输入优先 Hex，
        # 否则长度能被 4 整除的输入优先 Base64。
        options.sort(key=lambda item: item[0], reverse=True)
        best_score = options[0][0]
        tied = [item for item in options if item[0] == best_score]
        if len(tied) > 1:
            # 纯 hex 字符且不含 Base64 的 +/= 时优先 Hex；否则看是否有
            # 0x/空格等明确的 Hex 分隔符，再退回 Base64。
            stripped = text.strip()
            pure_hex = (
                hex_ok
                and not re.search(r"[+/=]", stripped)
                and re.fullmatch(r"[0-9a-fA-F]+", _normalize_hex(stripped))
            )
            preferred = "Hex" if (
                pure_hex or re.search(r"0[xX]|\\[xX]|[\s,;:_-]", text)
            ) else "Base64"
            tied.sort(key=lambda item: 0 if item[1] == preferred else 1)
            chosen = tied[0]
        else:
            chosen = options[0]
        _, method, data, _ = chosen
        if len(options) > 1:
            warnings.append("输入同时符合两种格式，已按文件头特征自动选择。")

    result = _detect(data, name_hint)
    if data and result.real_name == "未知" and len(data) >= 4:
        warnings.append("未命中常见文件头，仍可按 .bin 保存后继续分析。")
    return DecodedPayload(
        data=data,
        method=method,
        detected=result,
        default_name=_default_name(result, method),
        warnings=warnings,
    )


def encode_data(data: bytes, mode: str = "base64") -> str:
    if mode == "base64":
        return base64.b64encode(data).decode("ascii")
    if mode == "hex":
        return data.hex()
    raise DataToolError(f"未知的编码方式:{mode}")


def read_file(path: str | Path) -> bytes:
    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError as exc:
        raise DataToolError(f"读取文件失败:{exc}") from exc
    if size > MAX_DECODED_BYTES:
        raise DataToolError(
            f"文件过大({size / 1024 / 1024:.1f} MB)，"
            f"上限为 {MAX_DECODED_BYTES // 1024 // 1024} MB")
    try:
        return p.read_bytes()
    except OSError as exc:
        raise DataToolError(f"读取文件失败:{exc}") from exc


def human_size(size: int) -> str:
    if size < 1024:
        return f"{size} 字节"
    if size < 1024 * 1024:
        return f"{size / 1024:.2f} KiB"
    if size < 1024 * 1024 * 1024:
        return f"{size / 1024 / 1024:.2f} MiB"
    return f"{size / 1024 / 1024 / 1024:.2f} GiB"
