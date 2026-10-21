"""零宽字符隐写:U+200B 表 0,U+200C 表 1,8 位一组还原字节。"""

from __future__ import annotations

from core.codecs.base import CodecBase, CodecError

ZW0 = chr(0x200B)   # bit 0
ZW1 = chr(0x200C)   # bit 1


class ZeroWidthCodec(CodecBase):
    name = "零宽字符"
    category = "隐写编码"
    description = "U+200B=0,U+200C=1;可混入正常文本,解码自动提取"
    params = [("cover", "伪装文本(可空,编码时混入)", "")]

    def encode(self, text: str, **params) -> str:
        data = self.to_bytes(text)
        bits = "".join(f"{b:08b}" for b in data)
        hidden = "".join(ZW1 if bit == "1" else ZW0 for bit in bits)
        cover = params.get("cover", "")
        if cover:
            pos = len(cover) // 2
            return cover[:pos] + hidden + cover[pos:]
        return hidden

    def decode(self, text: str, **params) -> str:
        if not text:
            return ""
        bits = []
        for ch in text:
            if ch == ZW0:
                bits.append("0")
            elif ch == ZW1:
                bits.append("1")
        if not bits:
            raise CodecError("未检测到零宽字符(U+200B/U+200C)")
        if len(bits) % 8:
            raise CodecError(f"零宽字符位数({len(bits)})不是 8 的整数倍,数据可能不完整")
        data = bytes(int("".join(bits[i:i + 8]), 2) for i in range(0, len(bits), 8))
        return self.to_text(data)
