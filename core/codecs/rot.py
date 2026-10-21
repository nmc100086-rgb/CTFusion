"""ROT13 与 Atbash:均为自逆变换。"""

from __future__ import annotations

from core.codecs.base import CodecBase


class Rot13Codec(CodecBase):
    name = "ROT13"
    category = "古典密码"
    description = "字母循环偏移 13 位,自逆"

    _TABLE = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    )

    def encode(self, text: str, **p) -> str:
        return text.translate(self._TABLE)

    def decode(self, text: str, **p) -> str:
        return text.translate(self._TABLE)


class AtbashCodec(CodecBase):
    name = "Atbash"
    category = "古典密码"
    description = "Atbash(反字母表,旧称放射密码):字母表首尾互换(A<->Z),自逆"

    _TABLE = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba",
    )

    def encode(self, text: str, **p) -> str:
        return text.translate(self._TABLE)

    def decode(self, text: str, **p) -> str:
        return text.translate(self._TABLE)
