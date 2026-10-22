"""轻量编码特征检测:URL / Base64 / Hex 字符串。"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from core.analysis import strings

_URL_RE = re.compile(r"https?://[^\s\"'<>]{4,}")
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{16,})(?![0-9a-fA-F])")
_FLAG_RE = re.compile(r"\b(?:flag|ctf|key)\s*\{[^}\n]{0,300}\}", re.IGNORECASE)


@dataclass(frozen=True)
class Detection:
    kind: str
    offset: int
    text: str
    decoded: str = ""


def _printable(raw: bytes) -> bool:
    if not raw:
        return False
    text = raw.decode("utf-8", "ignore")
    if len(text) < 4:
        return False
    good = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return good / len(text) >= 0.85 or bool(_FLAG_RE.search(text))


def _decode_base64(text: str) -> str:
    padded = text + "=" * (-len(text) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return ""
    return raw.decode("utf-8", "replace") if _printable(raw) else ""


def _decode_hex(text: str) -> str:
    if len(text) % 2:
        return ""
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        return ""
    return raw.decode("utf-8", "replace") if _printable(raw) else ""


def detect_encodings(data: bytes, limit: int = 20,
                     scan_limit: int = 16 * 1024 * 1024) -> list[Detection]:
    """从可打印字符串中挑出 URL、可解码 Base64、可解码 Hex。"""
    found: list[Detection] = []
    seen: set[tuple[str, str]] = set()
    for offset, text in strings(data[:scan_limit], min_len=8, limit=5000):
        for match in _URL_RE.finditer(text):
            value = match.group(0)
            key = ("URL", value)
            if key not in seen:
                seen.add(key)
                found.append(Detection("URL", offset + match.start(), value))
        for match in _B64_RE.finditer(text):
            value = match.group(1)
            decoded = _decode_base64(value)
            key = ("Base64", value)
            if decoded and key not in seen:
                seen.add(key)
                found.append(Detection("Base64", offset + match.start(), value, decoded))
        for match in _HEX_RE.finditer(text):
            value = match.group(1)
            decoded = _decode_hex(value)
            key = ("Hex", value)
            if decoded and key not in seen:
                seen.add(key)
                found.append(Detection("Hex", offset + match.start(), value, decoded))
        if len(found) >= limit:
            break
    return found[:limit]
