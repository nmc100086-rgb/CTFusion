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
    description = "git 风格 Base85(RFC 1924 变体)"
    STD = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
    alphabet_hint = "留空使用标准 85 字符字母表"

    def encode(self, text: str, alphabet: str = "", **p) -> str:
        table = self._check_alphabet(alphabet)
        out = base64.b85encode(self.to_bytes(text)).decode()
        return self._translate(out, self.STD, table)

    def decode(self, text: str, alphabet: str = "", **p) -> str:
        table = self._check_alphabet(alphabet)
        s = _WS.sub("", text)
        s = self._translate(s, table, self.STD)
        try:
            return self.to_text(base64.b85decode(s))
        except (binascii.Error, ValueError) as e:
            raise CodecError(f"不是合法的 Base85:{e}")


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
    description = "可打印 ASCII(排除双引号)大数实现,与个别在线工具输出可能不同"
    AL92 = "".join(chr(i) for i in range(33, 126) if i != 34)  # 92 字符

    def encode(self, text: str, **p) -> str:
        return _bigint_encode(self.to_bytes(text), self.AL92)

    def decode(self, text: str, **p) -> str:
        return self.to_text(_bigint_decode(text, self.AL92, "Base92"))


class Base100Codec(CodecBase):
    name = "Base100"
    category = "Base 家族"
    description = "每字节映射为一个 emoji(U+1F300 起)"

    def encode(self, text: str, **p) -> str:
        out = bytearray()
        for b in self.to_bytes(text):
            out += bytes([0xF0, 0x9F, 0x8C + (b >> 6), 0x80 + (b & 0x3F)])
        return out.decode("utf-8")

    def decode(self, text: str, **p) -> str:
        raw = text.replace("\n", "").replace(" ", "").encode("utf-8")
        if len(raw) % 4:
            raise CodecError("不是合法的 Base100:长度不是 4 的倍数")
        out = bytearray()
        for i in range(0, len(raw), 4):
            f0, f1, f2, f3 = raw[i:i + 4]
            if f0 != 0xF0 or f1 != 0x9F or not (0x8C <= f2 <= 0x8F) or not (0x80 <= f3 <= 0xBF):
                raise CodecError("不是合法的 Base100:包含非 emoji 编码字符")
            out.append(((f2 - 0x8C) << 6) | (f3 - 0x80))
        return self.to_text(bytes(out))
