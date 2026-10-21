"""Base 家族编码:16/32/45/58/62/64/85/91/92/100。

Base16/32/64/85 基于标准库,支持自定义字母表;
Base45(RFC 9285)/Base58/Base62/Base91/Base92/Base100 为自实现;
Base58/62/92 支持自定义字母表。
"""

from __future__ import annotations

import base64
import binascii
import re

from core.codecs.base import CodecBase, CodecError

_WS = re.compile(r"\s+")


def _bigint_encode(data: bytes, table: str) -> str:
    """整段数据视为大整数做进制转换,前导零字节映射为 table[0]。"""
    if not data:
        return ""
    zeros = len(data) - len(data.lstrip(b"\x00"))
    num = int.from_bytes(data, "big")
    base = len(table)
    out = []
    while num:
        num, r = divmod(num, base)
        out.append(table[r])
    return table[0] * zeros + "".join(reversed(out))


def _bigint_decode(s: str, table: str, name: str) -> bytes:
    s = _WS.sub("", s)
    if not s:
        return b""
    rev = {}
    for i, c in enumerate(table):
        rev.setdefault(c, i)
    base = len(table)
    num = 0
    zeros = 0
    for i, c in enumerate(s):
        if c not in rev:
            raise CodecError(f"不是合法的 {name}:包含非法字符 {c!r}")
        if i == zeros and c == table[0]:
            zeros += 1
        num = num * base + rev[c]
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    return b"\x00" * zeros + body


class _StdBase(CodecBase, abstract=True):
    """标准库 Base(16/32/64/85)公共逻辑,支持自定义字母表映射。"""

    STD: str = ""
    need_alphabet = True

    def _check_alphabet(self, alphabet: str) -> str:
        if alphabet:
            if len(set(alphabet)) != len(self.STD):
                raise CodecError(
                    f"自定义字母表需为 {len(self.STD)} 个不重复字符(当前 {len(set(alphabet))} 个)")
            return alphabet
        return self.STD

    def _translate(self, s: str, src: str, dst: str) -> str:
        return s.translate(str.maketrans(src, dst))


class Base16Codec(_StdBase):
    name = "Base16"
    category = "Base 家族"
    description = "十六进制 Base 编码"
    STD = "0123456789ABCDEF"
    alphabet_hint = "留空使用标准 16 字符字母表"

    def encode(self, text: str, alphabet: str = "", **p) -> str:
        table = self._check_alphabet(alphabet)
        out = base64.b16encode(self.to_bytes(text)).decode()
        return self._translate(out, self.STD, table)

    def decode(self, text: str, alphabet: str = "", **p) -> str:
        table = self._check_alphabet(alphabet)
        s = _WS.sub("", text)
        s = self._translate(s, table, self.STD)
        try:
            return self.to_text(base64.b16decode(s.upper()))
        except (binascii.Error, ValueError) as e:
            raise CodecError(f"不是合法的 Base16:{e}")


class Base32Codec(_StdBase):
    name = "Base32"
    category = "Base 家族"
    description = "RFC 4648 Base32"
    STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    alphabet_hint = "留空使用标准 32 字符字母表"

    def encode(self, text: str, alphabet: str = "", **p) -> str:
        table = self._check_alphabet(alphabet)
        out = base64.b32encode(self.to_bytes(text)).decode()
        return self._translate(out, self.STD, table)

    def decode(self, text: str, alphabet: str = "", **p) -> str:
        table = self._check_alphabet(alphabet)
        s = _WS.sub("", text)
        s = self._translate(s, table, self.STD)
        try:
            return self.to_text(base64.b32decode(s.upper()))
        except (binascii.Error, ValueError) as e:
            raise CodecError(f"不是合法的 Base32:{e}")


class Base45Codec(CodecBase):
    name = "Base45"
    category = "Base 家族"
    description = "RFC 9285 Base45(常见于健康码/QR 场景)"
    AL45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

    def encode(self, text: str, **p) -> str:
        data = self.to_bytes(text)
        out = []
        for i in range(0, len(data) - 1, 2):
            x = data[i] * 256 + data[i + 1]
            out += [self.AL45[x % 45], self.AL45[(x // 45) % 45], self.AL45[x // 2025]]
        if len(data) % 2:
            b = data[-1]
            out += [self.AL45[b % 45], self.AL45[b // 45]]
        return "".join(out)

    def decode(self, text: str, **p) -> str:
        s = text.replace("\r", "").replace("\n", "")
        if len(s) % 3 == 1:
            raise CodecError("不是合法的 Base45:长度不合法(模 3 余 1)")
        data = bytearray()
        try:
            i = 0
            while i < len(s):
                if len(s) - i >= 3:
                    x = (self.AL45.index(s[i]) + self.AL45.index(s[i + 1]) * 45
                         + self.AL45.index(s[i + 2]) * 2025)
                    if x > 0xFFFF:
                        raise CodecError("不是合法的 Base45:编码值越界")
                    data += bytes([x // 256, x % 256])
                    i += 3
                else:
                    x = self.AL45.index(s[i]) + self.AL45.index(s[i + 1]) * 45
                    if x > 0xFF:
                        raise CodecError("不是合法的 Base45:编码值越界")
                    data.append(x)
                    i += 2
        except ValueError as e:
            bad = str(e).split("'")[1] if "'" in str(e) else "?"
            raise CodecError(f"不是合法的 Base45:包含非法字符 {bad!r}")
        return self.to_text(bytes(data))


class Base58Codec(CodecBase):
    name = "Base58"
    category = "Base 家族"
    description = "比特币风格 Base58(去除 0/O/I/l)"
    AL58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    need_alphabet = True
    alphabet_hint = "留空使用 BTC 标准 58 字符字母表"

    def _table(self, alphabet: str) -> str:
        if alphabet:
            if len(set(alphabet)) != 58:
                raise CodecError(f"自定义字母表需为 58 个不重复字符(当前 {len(set(alphabet))} 个)")
            return alphabet
        return self.AL58

    def encode(self, text: str, alphabet: str = "", **p) -> str:
        return _bigint_encode(self.to_bytes(text), self._table(alphabet))

    def decode(self, text: str, alphabet: str = "", **p) -> str:
        return self.to_text(_bigint_decode(text, self._table(alphabet), "Base58"))


class Base62Codec(CodecBase):
    name = "Base62"
    category = "Base 家族"
    description = "0-9A-Za-z 共 62 字符"
    AL62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    need_alphabet = True
    alphabet_hint = "留空使用标准 62 字符字母表"

    def _table(self, alphabet: str) -> str:
        if alphabet:
            if len(set(alphabet)) != 62:
                raise CodecError(f"自定义字母表需为 62 个不重复字符(当前 {len(set(alphabet))} 个)")
            return alphabet
        return self.AL62

    def encode(self, text: str, alphabet: str = "", **p) -> str:
        return _bigint_encode(self.to_bytes(text), self._table(alphabet))

    def decode(self, text: str, alphabet: str = "", **p) -> str:
        return self.to_text(_bigint_decode(text, self._table(alphabet), "Base62"))


class Base64Codec(_StdBase):
    name = "Base64"
    category = "Base 家族"
    description = "最常见的 Base 编码"
    STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    alphabet_hint = "留空使用标准 64 字符字母表"

    def encode(self, text: str, alphabet: str = "", **p) -> str:
        table = self._check_alphabet(alphabet)
        out = base64.b64encode(self.to_bytes(text)).decode()
        return self._translate(out, self.STD, table)

    def decode(self, text: str, alphabet: str = "", **p) -> str:
        table = self._check_alphabet(alphabet)
        s = _WS.sub("", text)
        s = self._translate(s, table, self.STD)
        # 宽容补齐 padding
        s += "=" * (-len(s) % 4)
        try:
            return self.to_text(base64.b64decode(s, validate=True))
        except (binascii.Error, ValueError) as e:
            raise CodecError(f"不是合法的 Base64:{e}")


class Base85Codec(_StdBase):
    name = "Base85"
    category = "Base 家族"
    description = "RFC 1924 Base85(不含逗号/句号/斜杠),与 Python base64.b85decode 兼容"
    STD = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
    alphabet_hint = "留空使用 RFC 1924 标准 85 字符字母表"

    def encode(self, text: str, alphabet: str = "", **p) -> str:
        table = self._check_alphabet(alphabet)
        out = base64.b85encode(self.to_bytes(text)).decode()
        return self._translate(out, self.STD, table)

    def decode(self, text: str, alphabet: str = "", **p) -> str:
        table = self._check_alphabet(alphabet)
        s = _WS.sub("", text)
        if not s:
            raise CodecError("请输入 Base85 编码内容")
        charset = set(table)
        for ch in s:
            if ch not in charset:
                raise CodecError(f"不是合法的 Base85:包含非法字符 {ch!r}(注意:逗号/句号/斜杠属于 Ascii85 变体)")
        s = self._translate(s, table, self.STD)
        try:
            return self.to_text(base64.b85decode(s))
        except (binascii.Error, ValueError) as e:
            raise CodecError(f"不是合法的 Base85:{e}")


class Ascii85Codec(CodecBase):
    """Adobe 原始 Ascii85:字母表从 '!' (33) 到 'u' (117) 连续 85 字符,
    包含逗号/句号/斜杠;算法与 Base85 相同(4 字节 -> 5 字符),
    Python 标准库 base64.a85encode/decode 即此版本。"""

    name = "Ascii85"
    category = "Base 家族"
    description = "Adobe 原始 Ascii85,含逗号/句号/斜杠;与 RFC 1924 Base85 是两种不同字母表"
    STD = '!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu'

    def encode(self, text: str, **p) -> str:
        return base64.a85encode(self.to_bytes(text)).decode()

    def decode(self, text: str, **p) -> str:
        s = _WS.sub("", text)
        s = s.strip("<>~").strip()
        if not s:
            return ""
        charset = set(self.STD)
        for ch in s:
            if ch not in charset:
                raise CodecError(f"不是合法的 Ascii85:包含非法字符 {ch!r}")
        try:
            return self.to_text(base64.a85decode(s))
        except (binascii.Error, ValueError) as e:
            raise CodecError(f"不是合法的 Ascii85:{e}")


class Base91Codec(CodecBase):
    name = "Base91"
    category = "Base 家族"
    description = "basE91(比 Base64 密度更高)"
    AL91 = ('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
            '!#$%&()*+,./:;<=>?@[]^_`{|}~"')

    def encode(self, text: str, **p) -> str:
        b = n = 0
        out = []
        for byte in self.to_bytes(text):
            b |= byte << n
            n += 8
            if n > 13:
                v = b & 8191
                if v > 88:
                    b >>= 13
                    n -= 13
                else:
                    v = b & 16383
                    b >>= 14
                    n -= 14
                out += [self.AL91[v % 91], self.AL91[v // 91]]
        if n:
            out.append(self.AL91[b % 91])
            if n > 7 or b > 90:
                out.append(self.AL91[b // 91])
        return "".join(out)

    def decode(self, text: str, **p) -> str:
        rev = {c: i for i, c in enumerate(self.AL91)}
        v = -1
        b = n = 0
        out = bytearray()
        for ch in text:
            if ch.isspace():
                continue
            if ch not in rev:
                raise CodecError(f"不是合法的 Base91:包含非法字符 {ch!r}")
            c = rev[ch]
            if v < 0:
                v = c
            else:
                v += c * 91
                b |= v << n
                n += 13 if (v & 8191) > 88 else 14
                while n > 7:
                    out.append(b & 255)
                    b >>= 8
                    n -= 8
                v = -1
        if v >= 0:
            out.append((b | (v << n)) & 255)
        return self.to_text(bytes(out))


class Base92Codec(CodecBase):
    name = "Base92"
    category = "Base 家族"
    description = "官方 13 位分块 Base92(91 字符字母表),行业标准实现"
    # 官方字母表: ! + #~_ (跳过双引号) + a~} 共 91 字符
    AL92 = "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_abcdefghijklmnopqrstuvwxyz{|}"

    def encode(self, text: str, **p) -> str:
        data = self.to_bytes(text)
        if not data:
            return "~"

        bit_buffer = 0
        bit_count = 0
        out = []
        for byte in data:
            bit_buffer = (bit_buffer << 8) | byte
            bit_count += 8
            while bit_count >= 13:
                chunk = bit_buffer >> (bit_count - 13)
                bit_buffer &= (1 << (bit_count - 13)) - 1
                bit_count -= 13
                out.append(self.AL92[chunk // 91])
                out.append(self.AL92[chunk % 91])

        if bit_count > 0:
            if bit_count < 7:
                chunk = bit_buffer << (6 - bit_count)
                out.append(self.AL92[chunk])
            else:
                chunk = bit_buffer << (13 - bit_count)
                out.append(self.AL92[chunk // 91])
                out.append(self.AL92[chunk % 91])

        return "".join(out)

    def decode(self, text: str, **p) -> str:
        s = _WS.sub("", text)
        if not s:
            raise CodecError("请输入 Base92 编码内容")
        if s == "~":
            return ""
        if len(s) == 1:
            raise CodecError("不是合法的 Base92:1 字符无法还原")

        rev = {c: i for i, c in enumerate(self.AL92)}
        bit_buffer = 0
        bit_count = 0
        out = bytearray()

        # 成对处理
        i = 0
        while i < len(s) - 1:
            c1, c2 = s[i], s[i + 1]
            if c1 not in rev or c2 not in rev:
                bad = c1 if c1 not in rev else c2
                raise CodecError(f"不是合法的 Base92:包含非法字符 {bad!r}")
            chunk = rev[c1] * 91 + rev[c2]
            if chunk >= 8192:
                raise CodecError("不是合法的 Base92:编码值越界")
            bit_buffer = (bit_buffer << 13) | chunk
            bit_count += 13
            while bit_count >= 8:
                out.append((bit_buffer >> (bit_count - 8)) & 0xFF)
                bit_buffer &= (1 << (bit_count - 8)) - 1
                bit_count -= 8
            i += 2

        # 末尾单字符(6 位填充)
        if i < len(s):
            c = s[i]
            if c not in rev:
                raise CodecError(f"不是合法的 Base92:末尾非法字符 {c!r}")
            bit_buffer = (bit_buffer << 6) | rev[c]
            bit_count += 6
            while bit_count >= 8:
                out.append((bit_buffer >> (bit_count - 8)) & 0xFF)
                bit_buffer &= (1 << (bit_count - 8)) - 1
                bit_count -= 8

        return self.to_text(bytes(out))
