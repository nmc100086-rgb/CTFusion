"""单向哈希:MD5。"""

from __future__ import annotations

import hashlib

from core.codecs.base import CodecBase, CodecError


class Md5Codec(CodecBase):
    name = "MD5"
    category = "哈希"
    description = "单向哈希,输出 32 位十六进制;不可逆"
    one_way = True
    detectable = False

    def encode(self, text: str, **p) -> str:
        return hashlib.md5(self.to_bytes(text)).hexdigest()

    def decode(self, text: str, **p) -> str:
        raise CodecError("MD5 是单向哈希,无法直接解码。可尝试在线彩虹表(如 cmd5)反查。")
