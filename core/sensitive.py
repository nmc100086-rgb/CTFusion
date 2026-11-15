"""Shared detection of interesting CTF output and filesystem-like strings."""

from __future__ import annotations

import re

FLAG_RE = re.compile(
    r"(?i)\b(?:flag|ctf|key)\s*\{[^}\n]{0,300}\}"
)
URL_RE = re.compile(r"(?i)\bhttps?://[^\s\"'<>]{4,}")
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
HASH_RE = re.compile(r"(?i)^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128})$")

_CREDENTIAL_RE = re.compile(
    r"(?i)\b(?:password|passwd|passcode|pwd|secret|token|api[_-]?key|"
    r"access[_-]?key|authorization)\b\s*[:=]\s*[^\s,;]{3,}"
)
_COMMON_CREDENTIAL_RE = re.compile(
    r"(?i)^(?:admin|administrator|root|guest|password|passw0rd|letmein|"
    r"qwerty|123456|changeme)$"
)
_PATH_RE = re.compile(
    r"""(?ix)
    (?:
        (?:^|[\s"'`=(:,])
        (?:
            [a-z]:[\\/]
            | \.{1,2}[\\/]
            | /
        )
        [^\s"'`<>|]{2,}
    )
    """
)

CATEGORY_TEXT = "文本"
CATEGORY_FLAG = "Flag"
CATEGORY_URL = "URL"
CATEGORY_CREDENTIAL = "凭据"
CATEGORY_PATH = "路径"
CATEGORY_EMAIL = "邮箱"
CATEGORY_HASH = "哈希"
CATEGORY_SECRET = "疑似密码"


def has_flag(text: str) -> bool:
    return bool(FLAG_RE.search(text))


def _looks_like_opaque_secret(text: str) -> bool:
    value = text.strip()
    if not 6 <= len(value) <= 96 or any(ch.isspace() for ch in value):
        return False
    if any(not ch.isprintable() for ch in value):
        return False
    classes = sum((
        any(ch.islower() for ch in value),
        any(ch.isupper() for ch in value),
        any(ch.isdigit() for ch in value),
        any(not ch.isalnum() for ch in value),
    ))
    # Require at least one symbol. This keeps nested Base64 strings flowing
    # through another decode layer instead of treating them as passwords.
    return classes >= 4 and not value.isalpha()


def classify_output(text: str, *, allow_suspected_secret: bool = False) -> str:
    """Classify useful smart-decoder output without treating all text as a hit."""
    if not text:
        return CATEGORY_TEXT
    if has_flag(text):
        return CATEGORY_FLAG
    if URL_RE.search(text):
        return CATEGORY_URL
    if _CREDENTIAL_RE.search(text) or _COMMON_CREDENTIAL_RE.fullmatch(text.strip()):
        return CATEGORY_CREDENTIAL
    if _PATH_RE.search(text):
        return CATEGORY_PATH
    if EMAIL_RE.fullmatch(text.strip()):
        return CATEGORY_EMAIL
    if HASH_RE.fullmatch(text.strip()):
        return CATEGORY_HASH
    if allow_suspected_secret and _looks_like_opaque_secret(text):
        return CATEGORY_SECRET
    return CATEGORY_TEXT


def is_sensitive(text: str) -> bool:
    return classify_output(text) != CATEGORY_TEXT
