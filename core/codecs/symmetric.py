"""对称密码:AES(ECB/CBC,PKCS7)与 RC4。密文统一以 Base64 或 Hex 表示。"""

from __future__ import annotations

import base64
import binascii
import os
import re

from core.codecs.base import CodecBase, CodecError


def _parse_material(s: str, what: str, lengths: tuple[int, ...],
                     hex_lens: tuple[int, ...], fmt: str = "auto") -> bytes:
    """解析密钥/IV。

    fmt=auto: 默认按 UTF-8;只有显式 "hex:" 前缀才按 hex 解析。
    fmt=utf8: 强制按 UTF-8。
    fmt=hex:  强制按 hex 解析(也可继续使用 "hex:" 前缀)。
    这样 "deadbeef" 这类普通密钥不会被悄悄当成 4 个 hex 字节。
    """
    raw = s.strip()
    if not raw:
        raise CodecError(f"请输入{what}")
    fmt = (fmt or "auto").strip().lower()
    if fmt not in ("auto", "utf8", "hex"):
        raise CodecError("密钥/IV 格式仅支持 auto、utf8 或 hex")

    if fmt != "utf8" and raw.lower().startswith("hex:"):
        raw = raw[4:].strip()
        use_hex = True
    else:
        use_hex = fmt == "hex"

    if use_hex:
        if not raw:
            raise CodecError(f"请输入{what}")
        if len(raw) % 2:
            raise CodecError(f"{what}的 hex 长度必须为偶数(当前 {len(raw)} 个字符)")
        if hex_lens and len(raw) not in hex_lens:
            want = "/".join(str(x) for x in hex_lens)
            raise CodecError(f"{what}的 hex 长度需为 {want} 个字符(当前 {len(raw)} 个)")
        try:
            return bytes.fromhex(raw)
        except ValueError:
            raise CodecError(f"{what}不是合法的 hex")

    data = raw.encode("utf-8")
    if lengths and len(data) not in lengths:
        want = "/".join(str(x) for x in lengths)
        raise CodecError(f"{what}需为 {want} 字节(当前 {len(data)} 字节)")
    return data


def _fmt_out(data: bytes, fmt: str) -> str:
    return base64.b64encode(data).decode() if fmt == "base64" else data.hex()


def _fmt_in(text: str, fmt: str, name: str) -> bytes:
    s = re.sub(r"\s+", "", text)
    try:
        if fmt == "base64":
            s += "=" * (-len(s) % 4)
            return base64.b64decode(s, validate=True)
        return bytes.fromhex(s)
    except (binascii.Error, ValueError):
        raise CodecError(f"密文不是合法的 {fmt} 格式({name})")


def _parse_fmt(params: dict) -> str:
    fmt = params.get("format", "base64").strip().lower()
    if fmt not in ("base64", "hex"):
        raise CodecError("密文格式仅支持 base64 或 hex")
    return fmt


class AesCodec(CodecBase):
    name = "AES"
    category = "对称密码"
    description = "AES-ECB/CBC;支持 PKCS7/无填充/零填充/ISO10126;密钥 16/24/32 字节"
    need_key = True
    key_hint = "16/24/32 字节字符串;hex 密钥用 hex: 前缀,或在参数区选 key_format=hex"
    need_iv = True
    auto_key = True
    auto_iv = True
    params = [
        ("mode", "模式(ECB/CBC)", "ECB"),
        ("padding", "填充方式", "pkcs7"),
        ("format", "密文格式(base64/hex)", "base64"),
        ("key_format", "密钥格式(auto/utf8/hex)", "auto"),
        ("iv_format", "IV 格式(auto/utf8/hex)", "auto"),
    ]
    param_choices = {
        "mode": [
            ("ECB", "ECB"),
            ("CBC", "CBC"),
        ],
        "padding": [
            ("PKCS7", "pkcs7"),
            ("无填充", "none"),
            ("零填充", "zero"),
            ("ISO10126", "iso10126"),
        ],
        "format": [
            ("base64", "base64"),
            ("hex", "hex"),
        ],
        "key_format": [
            ("auto", "auto"),
            ("utf8", "utf8"),
            ("hex", "hex"),
        ],
        "iv_format": [
            ("auto", "auto"),
            ("utf8", "utf8"),
            ("hex", "hex"),
        ],
    }

    def _cipher(self, key_b: bytes, iv: str, mode: str, iv_format: str = "auto"):
        from Crypto.Cipher import AES
        if mode == "ECB":
            return AES.new(key_b, AES.MODE_ECB)
        iv_b = _parse_material(iv, "IV", (16,), (32,), iv_format)
        return AES.new(key_b, AES.MODE_CBC, iv_b)

    def _mode(self, params: dict) -> str:
        mode = str(params.get("mode", "ECB")).strip().upper()
        if mode not in ("ECB", "CBC"):
            raise CodecError("模式仅支持 ECB 或 CBC")
        return mode

    def _padding(self, params: dict) -> str:
        raw = str(params.get("padding", "pkcs7")).strip().lower()
        aliases = {
            "pkcs7": "pkcs7", "pkcs#7": "pkcs7", "pkcs 7": "pkcs7",
            "none": "none", "无填充": "none", "no": "none",
            "zero": "zero", "零填充": "zero",
            "iso10126": "iso10126", "iso": "iso10126",
        }
        mode = aliases.get(raw)
        if mode is None:
            raise CodecError("填充方式仅支持 PKCS7、无填充、零填充、ISO10126")
        return mode

    @staticmethod
    def _pad_data(data: bytes, mode: str) -> bytes:
        from Crypto.Util.Padding import pad
        if mode == "pkcs7":
            return pad(data, 16)
        if mode == "none":
            if len(data) % 16:
                raise CodecError("无填充模式要求明文长度是 16 的整数倍")
            return data
        if mode == "zero":
            left = (-len(data)) % 16
            return data + b"\x00" * left
        # ISO10126: 随机填充,最后一个字节为填充长度
        n = 16 - len(data) % 16
        return data + os.urandom(n - 1) + bytes([n])

    @staticmethod
    def _unpad_data(data: bytes, mode: str) -> bytes:
        from Crypto.Util.Padding import unpad
        if mode == "pkcs7":
            try:
                return unpad(data, 16)
            except ValueError:
                raise CodecError("解密失败:PKCS7 填充不合法,密钥/IV/模式可能不正确")
        if mode == "none":
            return data
        if mode == "zero":
            return data.rstrip(b"\x00")
        # ISO10126
        if not data:
            raise CodecError("解密失败:ISO10126 填充为空")
        n = data[-1]
        if not (1 <= n <= 16) or n > len(data):
            raise CodecError("解密失败:ISO10126 填充不合法,密钥/IV/模式可能不正确")
        return data[:-n]

    def encode(self, text: str, key: str = "", iv: str = "", **params) -> str:
        key_b = _parse_material(key, "AES 密钥", (16, 24, 32), (32, 48, 64),
                                params.get("key_format", "auto"))
        mode = self._mode(params)
        fmt = _parse_fmt(params)
        cipher = self._cipher(key_b, iv, mode, params.get("iv_format", "auto"))
        ct = cipher.encrypt(self._pad_data(self.to_bytes(text), self._padding(params)))
        return _fmt_out(ct, fmt)

    def decode(self, text: str, key: str = "", iv: str = "", **params) -> str:
        key_b = _parse_material(key, "AES 密钥", (16, 24, 32), (32, 48, 64),
                                params.get("key_format", "auto"))
        mode = self._mode(params)
        fmt = _parse_fmt(params)
        ct = _fmt_in(text, fmt, self.name)
        if len(ct) % 16:
            raise CodecError("解密失败:密文长度不是 16 的倍数")
        cipher = self._cipher(key_b, iv, mode, params.get("iv_format", "auto"))
        try:
            pt = cipher.decrypt(ct)
        except ValueError as e:
            raise CodecError(f"解密失败:{e}")
        pt = self._unpad_data(pt, self._padding(params))
        return self.to_text(pt)


class Rc4Codec(CodecBase):
    name = "RC4"
    category = "对称密码"
    description = "RC4 流密码;支持 string/hex/base64 明文格式"
    need_key = True
    auto_key = True
    key_hint = "任意长度字符串;hex 密钥用 hex: 前缀,或在参数区选 key_format=hex"
    params = [
        ("plaintext_format", "明文格式(string/hex/base64)", "string"),
        ("format", "密文格式(base64/hex)", "base64"),
        ("key_format", "密钥格式(auto/utf8/hex)", "auto"),
    ]
    param_choices = {
        "plaintext_format": [
            ("string", "string"),
            ("hex", "hex"),
            ("base64", "base64"),
        ],
        "format": [
            ("base64", "base64"),
            ("hex", "hex"),
        ],
        "key_format": [
            ("auto", "auto"),
            ("utf8", "utf8"),
            ("hex", "hex"),
        ],
    }

    @staticmethod
    def _plain_format(params: dict) -> str:
        raw = str(params.get("plaintext_format", "string")).strip().lower()
        aliases = {
            "string": "string", "str": "string", "text": "string", "字符串": "string",
            "hex": "hex", "16进制": "hex",
            "base64": "base64", "b64": "base64",
        }
        fmt = aliases.get(raw)
        if fmt is None:
            raise CodecError("明文格式仅支持 string、hex 或 base64")
        return fmt

    def _plain_in(self, text: str, fmt: str) -> bytes:
        if fmt == "string":
            return self.to_bytes(text)
        s = re.sub(r"\s+", "", text)
        try:
            if fmt == "hex":
                return bytes.fromhex(s)
            s += "=" * (-len(s) % 4)
            return base64.b64decode(s, validate=True)
        except (binascii.Error, ValueError):
            raise CodecError(f"明文不是合法的 {fmt} 格式")

    def _plain_out(self, data: bytes, fmt: str) -> str:
        if fmt == "string":
            return self.to_text(data)
        if fmt == "hex":
            return data.hex()
        return base64.b64encode(data).decode()

    def _crypt(self, text: str, key: str, params: dict, encrypting: bool) -> str:
        from Crypto.Cipher import ARC4
        key_b = _parse_material(key, "RC4 密钥", (), (),
                                params.get("key_format", "auto"))
        cipher_fmt = _parse_fmt(params)
        plain_fmt = self._plain_format(params)
        cipher = ARC4.new(key_b)
        if encrypting:
            plain = self._plain_in(text, plain_fmt)
            return _fmt_out(cipher.encrypt(plain), cipher_fmt)
        ciphertext = _fmt_in(text, cipher_fmt, self.name)
        return self._plain_out(cipher.encrypt(ciphertext), plain_fmt)

    def encode(self, text: str, key: str = "", **params) -> str:
        return self._crypt(text, key, params, encrypting=True)

    def decode(self, text: str, key: str = "", **params) -> str:
        return self._crypt(text, key, params, encrypting=False)
