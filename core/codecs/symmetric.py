"""对称密码:AES(ECB/CBC,PKCS7)与 RC4。密文统一以 Base64 或 Hex 表示。"""

from __future__ import annotations

import base64
import binascii
import re

from core.codecs.base import CodecBase, CodecError


def _parse_bytes(s: str, what: str, lengths: tuple[int, ...], hex_lens: tuple[int, ...]) -> bytes:
    """解析密钥/IV:优先按 hex(长度匹配时),否则按 UTF-8。"""
    raw = s.strip()
    if not raw:
        raise CodecError(f"请输入{what}")
    if re.fullmatch(r"[0-9a-fA-F]+", raw) and len(raw) in hex_lens:
        return bytes.fromhex(raw)
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
    description = "AES-ECB/CBC,PKCS7 填充;密钥 16/24/32 字节,支持 hex"
    need_key = True
    key_hint = "16/24/32 字节字符串,或 32/48/64 位 hex"
    need_iv = True
    params = [
        ("mode", "模式(ECB/CBC)", "ECB"),
        ("format", "密文格式(base64/hex)", "base64"),
    ]

    def _cipher(self, key_b: bytes, iv: str, mode: str, encrypting: bool):
        from Crypto.Cipher import AES
        if mode == "ECB":
            return AES.new(key_b, AES.MODE_ECB)
        iv_b = _parse_bytes(iv, "IV", (16,), (32,))
        return AES.new(key_b, AES.MODE_CBC, iv_b)

    def _mode(self, params: dict) -> str:
        mode = params.get("mode", "ECB").strip().upper()
        if mode not in ("ECB", "CBC"):
            raise CodecError("模式仅支持 ECB 或 CBC")
        return mode

    def encode(self, text: str, key: str = "", iv: str = "", **params) -> str:
        from Crypto.Util.Padding import pad
        key_b = _parse_bytes(key, "AES 密钥", (16, 24, 32), (32, 48, 64))
        mode = self._mode(params)
        fmt = _parse_fmt(params)
        cipher = self._cipher(key_b, iv, mode, True)
        ct = cipher.encrypt(pad(self.to_bytes(text), 16))
        return _fmt_out(ct, fmt)

    def decode(self, text: str, key: str = "", iv: str = "", **params) -> str:
        from Crypto.Util.Padding import unpad
        key_b = _parse_bytes(key, "AES 密钥", (16, 24, 32), (32, 48, 64))
        mode = self._mode(params)
        fmt = _parse_fmt(params)
        ct = _fmt_in(text, fmt, self.name)
        if len(ct) % 16:
            raise CodecError("解密失败:密文长度不是 16 的倍数")
        cipher = self._cipher(key_b, iv, mode, False)
        try:
            pt = unpad(cipher.decrypt(ct), 16)
        except ValueError:
            raise CodecError("解密失败:密钥/IV/模式可能不正确,或密文已损坏")
        return self.to_text(pt)


class Rc4Codec(CodecBase):
    name = "RC4"
    category = "对称密码"
    description = "RC4 流密码;密钥任意长度,支持 hex"
    need_key = True
    key_hint = "任意长度字符串,或 hex"
    params = [("format", "密文格式(base64/hex)", "base64")]

    def _crypt(self, text: str, key: str, params: dict, fmt_out: bool) -> str:
        from Crypto.Cipher import ARC4
        raw = key.strip()
        if not raw:
            raise CodecError("请输入 RC4 密钥")
        if re.fullmatch(r"[0-9a-fA-F]+", raw) and len(raw) % 2 == 0 and len(raw) >= 2:
            key_b = bytes.fromhex(raw)
        else:
            key_b = raw.encode("utf-8")
        fmt = _parse_fmt(params)
        cipher = ARC4.new(key_b)
        if fmt_out:
            return _fmt_out(cipher.encrypt(self.to_bytes(text)), fmt)
        return self.to_text(cipher.encrypt(_fmt_in(text, fmt, self.name)))

    def encode(self, text: str, key: str = "", **params) -> str:
        return self._crypt(text, key, params, fmt_out=True)

    def decode(self, text: str, key: str = "", **params) -> str:
        return self._crypt(text, key, params, fmt_out=False)
