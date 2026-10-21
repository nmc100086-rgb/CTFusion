"""UUencode 与 XXencode:按行编码,自动跳过 begin/end 头尾行。"""

from __future__ import annotations

import binascii

from core.codecs.base import CodecBase, CodecError


class UueCodec(CodecBase):
    name = "UUencode"
    category = "文本编码"
    description = "Unix-to-Unix 编码,每行 45 字节;自动跳过 begin/end 行"

    def encode(self, text: str, **p) -> str:
        data = self.to_bytes(text)
        lines = []
        for i in range(0, len(data), 45):
            lines.append(binascii.b2a_uu(data[i:i + 45]).decode("ascii").rstrip("\n"))
        return "\n".join(lines)

    def decode(self, text: str, **p) -> str:
        if not text.strip():
            return ""
        out = bytearray()
        for raw in text.strip().splitlines():
            line = raw.rstrip("\n")
            if not line or line in ("`", "end") or line.startswith("begin"):
                continue
            # 部分编码器用反引号代替空格
            line = line.replace("`", " ")
            try:
                out += binascii.a2b_uu(line.encode("ascii"))
            except (binascii.Error, UnicodeEncodeError) as e:
                raise CodecError(f"不是合法的 UUencode:{e}")
        if not out:
            raise CodecError("不是合法的 UUencode:未解析到有效数据行")
        return self.to_text(bytes(out))


class XueCodec(CodecBase):
    name = "XXencode"
    category = "文本编码"
    description = "结构与 UUencode 相同,使用 +-0-9A-Za-z 字母表"
    ALXX = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    def encode(self, text: str, **p) -> str:
        data = self.to_bytes(text)
        lines = []
        for i in range(0, len(data), 45):
            chunk = data[i:i + 45]
            line = [chr(len(chunk) + 32)]
            for j in range(0, len(chunk), 3):
                g = chunk[j:j + 3].ljust(3, b"\x00")
                n = (g[0] << 16) | (g[1] << 8) | g[2]
                line += [self.ALXX[(n >> 18) & 63], self.ALXX[(n >> 12) & 63],
                         self.ALXX[(n >> 6) & 63], self.ALXX[n & 63]]
            lines.append("".join(line))
        return "\n".join(lines)

    def decode(self, text: str, **p) -> str:
        if not text.strip():
            return ""
        out = bytearray()
        for raw in text.strip().splitlines():
            if not raw or raw.startswith("begin") or raw == "end":
                continue
            n = ord(raw[0]) - 32
            if not (0 < n <= 45):
                raise CodecError(f"不是合法的 XXencode:行长度标记非法({raw[0]!r})")
            body = raw[1:]
            need = ((n + 2) // 3) * 4
            if len(body) < need:
                raise CodecError("不是合法的 XXencode:数据长度不足")
            vals = []
            for c in body[:need]:
                if c not in self.ALXX:
                    raise CodecError(f"不是合法的 XXencode:包含非法字符 {c!r}")
                vals.append(self.ALXX.index(c))
            cnt = 0
            for j in range(0, len(vals), 4):
                v = (vals[j] << 18) | (vals[j + 1] << 12) | (vals[j + 2] << 6) | vals[j + 3]
                for shift in (16, 8, 0):
                    if cnt < n:
                        out.append((v >> shift) & 0xFF)
                        cnt += 1
        if not out:
            raise CodecError("不是合法的 XXencode:未解析到有效数据行")
        return self.to_text(bytes(out))
