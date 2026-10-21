"""文本类简单编码:Hex / URL / ASCII 码 / Quoted-printable / 进制转换。"""

from __future__ import annotations

import binascii
import quopri
import re
from urllib.parse import quote, unquote_plus

from core.codecs.base import CodecBase, CodecError


class HexCodec(CodecBase):
    name = "Hex"
    category = "文本编码"
    description = "十六进制,解码自动忽略空格与 0x 前缀"

    def encode(self, text: str, **p) -> str:
        return self.to_bytes(text).hex()

    def decode(self, text: str, **p) -> str:
        s = re.sub(r"0x", "", text, flags=re.IGNORECASE)
        s = re.sub(r"[\s,]+", "", s)
        if len(s) % 2:
            raise CodecError("不是合法的 Hex:长度为奇数")
        try:
            return self.to_text(bytes.fromhex(s))
        except ValueError as e:
            raise CodecError(f"不是合法的 Hex:{e}")


class UrlCodec(CodecBase):
    name = "URL 编码"
    category = "文本编码"
    description = "Percent-Encoding;解码时 + 号视为空格(兼容表单编码)"

    def encode(self, text: str, **p) -> str:
        return quote(self.to_bytes(text), safe="")

    def decode(self, text: str, **p) -> str:
        try:
            return self.to_text(unquote_plus(text, errors="surrogateescape").encode(
                "utf-8", errors="surrogateescape"))
        except Exception:
            # unquote_plus 本身几乎不抛错,兜底按原样返回字节流
            try:
                return unquote_plus(text)
            except Exception as e:
                raise CodecError(f"URL 解码失败:{e}")


class AsciiCodec(CodecBase):
    name = "ASCII 码"
    category = "文本编码"
    description = "字符 <-> 码点序列(支持十进制/0x 十六进制,空格或逗号分隔)"

    def encode(self, text: str, **p) -> str:
        return " ".join(str(ord(c)) for c in text)

    def decode(self, text: str, **p) -> str:
        if not text.strip():
            return ""
        tokens = re.split(r"[\s,]+", text.strip())
        if not tokens or tokens == [""]:
            raise CodecError("请输入以空格/逗号分隔的码点序列")
        chars = []
        for tok in tokens:
            try:
                # 0x/0b/0o 用 base=0,普通十进制允许 065 这类前导零写法
                base = 0 if tok.lower().startswith(("0x", "0b", "0o")) else 10
                cp = int(tok, base)
                if 0xD800 <= cp <= 0xDFFF:
                    raise CodecError(f"码点 {cp} 位于 Unicode 代理区,不能单独解码")
                chars.append(chr(cp))
            except CodecError:
                raise
            except (ValueError, OverflowError):
                raise CodecError(f"无法识别的码点:{tok!r}(支持十进制或 0x 前缀十六进制)")
        return "".join(chars)


class QPCodec(CodecBase):
    name = "Quoted-printable"
    category = "文本编码"
    description = "邮件常用 QP 编码(=XX 形式)"

    def encode(self, text: str, **p) -> str:
        return quopri.encodestring(self.to_bytes(text), quotetabs=True).decode("ascii")

    def decode(self, text: str, **p) -> str:
        try:
            return self.to_text(quopri.decodestring(self.to_bytes(text)))
        except Exception as e:
            raise CodecError(f"Quoted-printable 解码失败:{e}")


class BaseConvertCodec(CodecBase):
    name = "进制转换"
    category = "进制"
    description = "2/8/10/16 进制互转;编码按 源→目标,解码按 目标→源;支持空格或逗号分隔的多组数值"
    detectable = False   # 歧义太大,不参与一键智能解码
    params = [
        ("from_base", "源进制(2/8/10/16)", "10"),
        ("to_base", "目标进制(2/8/10/16)", "16"),
    ]

    _DIGITS = "0123456789abcdef"
    _PREFIX = {2: "0b", 8: "0o", 16: "0x"}

    def _convert(self, text: str, from_base: int, to_base: int) -> str:
        if not text.strip():
            return ""
        tokens = re.split(r"[\s,]+", text.strip())
        if not tokens or tokens == [""]:
            raise CodecError("请输入要转换的数值(可多组,空格/逗号分隔)")
        out = []
        prefix = self._PREFIX.get(from_base, "")
        for tok in tokens:
            if prefix and tok.lower().startswith(prefix):
                tok = tok[len(prefix):]
            try:
                num = int(tok, from_base)
            except ValueError:
                raise CodecError(f"{tok!r} 不是合法的 {from_base} 进制数")
            if num < 0:
                raise CodecError("暂不支持负数")
            if to_base == 10:
                out.append(str(num))
            else:
                digits = self._DIGITS[:to_base]
                if num == 0:
                    out.append("0")
                else:
                    s = ""
                    while num:
                        num, r = divmod(num, to_base)
                        s = digits[r] + s
                    out.append(s.upper() if to_base == 16 else s)
        return " ".join(out)

    def _parse_bases(self, params: dict) -> tuple[int, int]:
        try:
            fb = int(params.get("from_base", "10"))
            tb = int(params.get("to_base", "16"))
        except ValueError:
            raise CodecError("进制参数必须是数字 2/8/10/16")
        if fb not in (2, 8, 10, 16) or tb not in (2, 8, 10, 16):
            raise CodecError("仅支持 2/8/10/16 进制")
        return fb, tb

    def encode(self, text: str, **params) -> str:
        fb, tb = self._parse_bases(params)
        return self._convert(text, fb, tb)

    def decode(self, text: str, **params) -> str:
        # 编码是 源→目标,解码必须反过来 目标→源
        fb, tb = self._parse_bases(params)
        return self._convert(text, tb, fb)
