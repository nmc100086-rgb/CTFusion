"""单向哈希:MD5。"""

from __future__ import annotations

import hashlib

from core.codecs.base import CodecBase, CodecError


class Md5Codec(CodecBase):
    name = "MD5"
    category = "哈希"
    description = "单向哈希;编码输出 16/32 位、大小写四种格式;不可逆"
    one_way = True
    detectable = False

    def encode(self, text: str, **p) -> str:
        digest = hashlib.md5(self.to_bytes(text)).hexdigest()
        short = digest[8:24]
        return "\n".join((
            f"MD5-16 位小写: {short}",
            f"MD5-16 位大写: {short.upper()}",
            f"MD5-32 位小写: {digest}",
            f"MD5-32 位大写: {digest.upper()}",
        ))

    def decode(self, text: str, **p) -> str:
        raise CodecError(
            "MD5 是单向哈希,无法从哈希还原明文。"
            "16 位只是 32 位中间 16 位,大小写只是十六进制字母大小写。"
        )
