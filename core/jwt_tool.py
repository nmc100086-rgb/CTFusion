"""JWT 解析与生成/伪造(HS256/384/512、none、RS256)。"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any


class JwtError(ValueError):
    pass


@dataclass
class DecodedJwt:
    header_text: str
    payload_text: str
    signature_text: str
    header: dict[str, Any]
    payload: dict[str, Any]
    valid: bool | None = None


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + padding)
    except (ValueError, TypeError) as e:
        raise JwtError(f"Base64URL 解码失败:{e}") from e


def _json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


def decode(token: str) -> DecodedJwt:
    token = token.strip()
    if not token:
        raise JwtError("Token 为空")
    parts = token.split(".")
    if len(parts) != 3:
        raise JwtError("JWT 必须由 header.payload.signature 三部分组成")
    try:
        header = json.loads(b64url_decode(parts[0]).decode("utf-8"))
        payload = json.loads(b64url_decode(parts[1]).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise JwtError(f"JWT JSON 解析失败:{e}") from e
    return DecodedJwt(_json_text(header), _json_text(payload), parts[2],
                      header, payload)


def _hs_sign(alg: str, secret: bytes, signing_input: bytes) -> bytes:
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
              "HS512": hashlib.sha512}.get(alg)
    if digest is None:
        raise JwtError(f"不支持的 HMAC 算法:{alg}")
    return hmac.new(secret, signing_input, digest).digest()


def _rs_sign(secret: str, signing_input: bytes) -> bytes:
    try:
        from Crypto.Hash import SHA256
        from Crypto.Signature import pkcs1_15
        from Crypto.PublicKey import RSA
    except ImportError as e:
        raise JwtError("RS256 需要 pycryptodome") from e
    try:
        key = RSA.import_key(secret)
    except (ValueError, IndexError, TypeError) as e:
        raise JwtError(f"RSA 私钥解析失败:{e}") from e
    return pkcs1_15.new(key).sign(SHA256.new(signing_input))


def encode(payload: dict[str, Any], secret: str = "", alg: str = "HS256",
           header: dict[str, Any] | None = None) -> str:
    header = dict(header or {"typ": "JWT", "alg": alg})
    header["alg"] = alg
    header_part = b64url_encode(
        json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    payload_part = b64url_encode(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_part}.{payload_part}".encode("ascii")
    if alg == "none":
        signature = ""
    elif alg in ("HS256", "HS384", "HS512"):
        signature = b64url_encode(_hs_sign(alg, secret.encode("utf-8"), signing_input))
    elif alg == "RS256":
        signature = b64url_encode(_rs_sign(secret, signing_input))
    else:
        raise JwtError(f"不支持的算法:{alg}")
    return f"{header_part}.{payload_part}.{signature}"


def verify(token: str, secret: str) -> bool:
    parts = token.strip().split(".")
    if len(parts) != 3:
        return False
    decoded = decode(token)
    alg = str(decoded.header.get("alg", ""))
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    try:
        expected = b64url_decode(parts[2])
    except JwtError:
        return False
    if alg == "none":
        return expected == b""
    if alg in ("HS256", "HS384", "HS512"):
        actual = _hs_sign(alg, secret.encode("utf-8"), signing_input)
        return hmac.compare_digest(actual, expected)
    if alg == "RS256":
        try:
            from Crypto.Hash import SHA256
            from Crypto.Signature import pkcs1_15
            from Crypto.PublicKey import RSA

            key = RSA.import_key(secret)
            pkcs1_15.new(key).verify(SHA256.new(signing_input), expected)
            return True
        except Exception:
            return False
    return False


def pretty_json(text: str) -> str:
    try:
        return _json_text(json.loads(text))
    except json.JSONDecodeError as e:
        raise JwtError(f"JSON 格式错误:{e}") from e
