"""古典密码:凯撒 / 维吉尼亚 / 栅栏 / 曲路 / 培根 / 摩斯 / 猪圈。"""

from __future__ import annotations

import math
import re

from core.codecs.base import CodecBase, CodecError, readability


def _shift_char(ch: str, shift: int) -> str:
    if "a" <= ch <= "z":
        return chr((ord(ch) - 97 + shift) % 26 + 97)
    if "A" <= ch <= "Z":
        return chr((ord(ch) - 65 + shift) % 26 + 65)
    return ch


class CaesarCodec(CodecBase):
    name = "凯撒密码"
    category = "古典密码"
    description = "字母整体偏移;解码时偏移量留空即爆破全部 25 种"
    params = [("shift", "偏移量(留空=爆破)", "")]

    def _shift_text(self, text: str, shift: int) -> str:
        return "".join(_shift_char(c, shift) for c in text)

    def _parse_shift(self, params: dict, allow_empty: bool) -> int | None:
        raw = params.get("shift", "").strip()
        if not raw:
            if allow_empty:
                return None
            return 3
        try:
            return int(raw) % 26
        except ValueError:
            raise CodecError("偏移量必须是整数")

    def encode(self, text: str, **params) -> str:
        shift = self._parse_shift(params, allow_empty=False)
        return self._shift_text(text, shift)

    def decode(self, text: str, **params) -> str:
        shift = self._parse_shift(params, allow_empty=True)
        if shift is not None:
            return self._shift_text(text, -shift)
        # 爆破模式:按可读性从高到低列出全部可能
        ranked = sorted(
            ((self._shift_text(text, -s), s) for s in range(1, 26)),
            key=lambda t: readability(t[0]), reverse=True)
        return "\n".join(f"偏移 {s:>2}: {out}" for out, s in ranked)

    def best_decode(self, text: str) -> str:
        """供一键智能解码:直接返回最可能的单个结果(可读性 + 常见字母加权)。"""
        common = set("etaoinshrdluETAOINSHRDLU")

        def score(s: str) -> float:
            return readability(s) + 0.05 * sum(1 for c in s if c in common)

        return max((self._shift_text(text, -s) for s in range(1, 26)),
                   key=score, default="")


class VigenereCodec(CodecBase):
    name = "维吉尼亚"
    category = "古典密码"
    description = "多表替换,需要字母密钥"
    need_key = True
    key_hint = "字母密钥,如 KEY"

    def _run(self, text: str, key: str, decrypt: bool) -> str:
        shifts = [ord(c) - 97 for c in key.lower() if c.isalpha()]
        if not shifts:
            raise CodecError("维吉尼亚密钥需包含至少一个字母")
        out = []
        i = 0
        for ch in text:
            if ch.isalpha() and ch.isascii():
                s = shifts[i % len(shifts)]
                i += 1
                out.append(_shift_char(ch, -s if decrypt else s))
            else:
                out.append(ch)
        return "".join(out)

    def encode(self, text: str, key: str = "", **p) -> str:
        return self._run(text, key, decrypt=False)

    def decode(self, text: str, key: str = "", **p) -> str:
        return self._run(text, key, decrypt=True)


class RailFenceCodec(CodecBase):
    name = "栅栏密码"
    category = "古典密码"
    description = "之字形(W 型)栅栏,栏数为参数"
    params = [("rails", "栏数(>=2)", "3")]

    def _rails(self, params: dict) -> int:
        try:
            rails = int(params.get("rails", "3"))
        except ValueError:
            raise CodecError("栏数必须是整数")
        if rails < 2:
            raise CodecError("栏数必须 >= 2")
        return rails

    def _pattern(self, n: int, rails: int) -> list[int]:
        seq = []
        rail, step = 0, 1
        for _ in range(n):
            seq.append(rail)
            if rail == 0:
                step = 1
            elif rail == rails - 1:
                step = -1
            rail += step
        return seq

    def encode(self, text: str, **params) -> str:
        rails = self._rails(params)
        fence = [[] for _ in range(rails)]
        for ch, r in zip(text, self._pattern(len(text), rails)):
            fence[r].append(ch)
        return "".join("".join(row) for row in fence)

    def decode(self, text: str, **params) -> str:
        rails = self._rails(params)
        n = len(text)
        pattern = self._pattern(n, rails)
        counts = [pattern.count(r) for r in range(rails)]
        # 按栏切分密文
        rows = []
        idx = 0
        for c in counts:
            rows.append(list(text[idx:idx + c]))
            idx += c
        pos = [0] * rails
        out = []
        for r in pattern:
            out.append(rows[r][pos[r]])
            pos[r] += 1
        return "".join(out)


class RouteCodec(CodecBase):
    name = "曲路密码"
    category = "古典密码"
    description = "按行写入矩阵、按列读出;长度不足补 X"
    params = [("cols", "列数(>=2)", "5")]

    def _cols(self, params: dict) -> int:
        try:
            cols = int(params.get("cols", "5"))
        except ValueError:
            raise CodecError("列数必须是整数")
        if cols < 2:
            raise CodecError("列数必须 >= 2")
        return cols

    def encode(self, text: str, **params) -> str:
        cols = self._cols(params)
        n = len(text)
        rows = math.ceil(n / cols)
        padded = text + "X" * (rows * cols - n)
        return "".join(padded[r * cols + c] for c in range(cols) for r in range(rows))

    def decode(self, text: str, **params) -> str:
        cols = self._cols(params)
        n = len(text)
        if n % cols:
            raise CodecError(f"密文长度({n})不是列数({cols})的整数倍,无法还原")
        rows = n // cols
        # 密文按列存储,还原回行
        return "".join(text[c * rows + r] for r in range(rows) for c in range(cols))


class BaconCodec(CodecBase):
    name = "培根密码"
    category = "古典密码"
    description = "5 位 A/B 一组(24 字母表,I/J、U/V 合并);兼容 0/1 输入"

    _TABLE = {chr(65 + i): format(i, "05b").replace("0", "A").replace("1", "B")
              for i in range(26) if chr(65 + i) not in "JU"}

    def encode(self, text: str, **p) -> str:
        out = []
        for ch in text.upper():
            c = {"J": "I", "U": "V"}.get(ch, ch)
            if c in self._TABLE:
                out.append(self._TABLE[c])
            elif ch == " ":
                out.append("/")
        if not out:
            raise CodecError("输入中没有可编码的字母")
        return " ".join(out)

    def decode(self, text: str, **p) -> str:
        rev = {v: k for k, v in self._TABLE.items()}
        cleaned = "".join(
            {"0": "A", "1": "B"}.get(c, c) for c in text.upper() if c in "AB01")
        if len(cleaned) % 5:
            raise CodecError(f"培根码长度({len(cleaned)})不是 5 的整数倍")
        out = []
        for i in range(0, len(cleaned), 5):
            group = cleaned[i:i + 5]
            if group not in rev:
                raise CodecError(f"无法识别的培根码组:{group!r}")
            out.append(rev[group])
        return "".join(out)


class MorseCodec(CodecBase):
    name = "摩斯电码"
    category = "古典密码"
    description = "字母间空格分隔,单词间用 / 或多个空格"

    _TABLE = {
        "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
        "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
        "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
        "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
        "Y": "-.--", "Z": "--..",
        "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
        "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
        ".": ".-.-.-", ",": "--..--", "?": "..--..", "'": ".----.", "!": "-.-.--",
        "/": "-..-.", "(": "-.--.", ")": "-.--.-", "&": ".-...", ":": "---...",
        ";": "-.-.-.", "=": "-...-", "+": ".-.-.", "-": "-....-", "_": "..--.-",
        '"': ".-..-.", "$": "...-..-", "@": ".--.-.",
    }

    def encode(self, text: str, **p) -> str:
        words = []
        for word in text.split(" "):
            codes = []
            for ch in word.upper():
                if ch not in self._TABLE:
                    raise CodecError(f"摩斯电码不支持字符:{ch!r}")
                codes.append(self._TABLE[ch])
            words.append(" ".join(codes))
        return " / ".join(words)

    def decode(self, text: str, **p) -> str:
        rev = {v: k for k, v in self._TABLE.items()}
        text = text.strip()
        if not re.fullmatch(r"[.\-/\s]+", text):
            raise CodecError("不是合法的摩斯电码:仅允许包含 . - / 与空白")
        words = re.split(r"\s*/\s*|\s{2,}", text)
        out = []
        for word in words:
            chars = []
            for code in word.split():
                if code not in rev:
                    raise CodecError(f"无法识别的摩斯码:{code!r}")
                chars.append(rev[code])
            out.append("".join(chars))
        return " ".join(out)


class PigpenCodec(CodecBase):
    name = "猪圈密码"
    category = "古典密码"
    description = "猪圈密码的 Unicode 符号近似表示;图片题请对照图形"

    _GRID1 = ["┘", "┴", "└", "┤", "┼", "├", "┐", "┬", "┌"]       # A-I
    _GRID2 = [g + "∙" for g in _GRID1]                          # J-R
    _X1 = ["⋀", "⋁", "<", ">"]                                   # S-V
    _X2 = [x + "∙" for x in _X1]                                 # W-Z
    _TABLE = {chr(65 + i): sym for i, sym in enumerate(_GRID1 + _GRID2 + _X1 + _X2)}

    def encode(self, text: str, **p) -> str:
        out = []
        for ch in text.upper():
            if ch in self._TABLE:
                out.append(self._TABLE[ch])
            elif ch == " ":
                out.append("/")
            else:
                raise CodecError(f"猪圈密码仅支持英文字母,遇到:{ch!r}")
        return " ".join(out)

    def decode(self, text: str, **p) -> str:
        rev = {v: k for k, v in self._TABLE.items()}
        tokens = text.strip().split()
        if not tokens:
            raise CodecError("请输入以空格分隔的猪圈符号")
        out = []
        for tok in tokens:
            if tok == "/":
                out.append(" ")
            elif tok in rev:
                out.append(rev[tok])
            else:
                raise CodecError(f"无法识别的猪圈符号:{tok!r}")
        return "".join(out)
