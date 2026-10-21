"""古典密码:凯撒 / 维吉尼亚 / 栅栏 / 曲路 / 培根 / 摩斯 / 猪圈。"""

from __future__ import annotations

import re
from functools import lru_cache

from core.codecs.base import CodecBase, CodecError, readability


def _shift_char(ch: str, shift: int) -> str:
    if "a" <= ch <= "z":
        return chr((ord(ch) - 97 + shift) % 26 + 97)
    if "A" <= ch <= "Z":
        return chr((ord(ch) - 65 + shift) % 26 + 65)
    return ch


def _bool_param(params: dict, name: str, default: bool = True) -> bool:
    raw = str(params.get(name, "1" if default else "0")).strip().lower()
    return raw not in ("0", "false", "no", "off")


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
        if not text:
            return ""
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


class AffineCodec(CodecBase):
    name = "仿射密码"
    category = "古典密码"
    description = "仿射密码 E(x)=(a*x+b) mod 26; a 必须与 26 互素; 默认保留标点与大小写"
    detectable = False
    params = [
        ("a", "a(必须与26互素)", "5"),
        ("b", "b(0~25)", "8"),
        ("remove_punctuation", "移除标点 (Remove Punctuation)", "0"),
    ]
    param_choices = {
        "a": [(str(v), str(v)) for v in (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25)],
        "b": [(str(v), str(v)) for v in range(26)],
    }
    param_bool = {"remove_punctuation"}

    def _parse_key(self, params: dict) -> tuple[int, int]:
        try:
            a = int(str(params.get("a", "5")).strip())
            b = int(str(params.get("b", "8")).strip())
        except ValueError:
            raise CodecError("仿射密码的 a、b 必须是整数")
        if a not in (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25):
            raise CodecError("a 必须与 26 互素,可选 1,3,5,7,9,11,15,17,19,21,23,25")
        if not 0 <= b <= 25:
            raise CodecError("b 必须在 0~25 之间")
        return a, b

    def _run(self, text: str, a: int, b: int, decrypt: bool,
             remove_punctuation: bool) -> str:
        inv = pow(a, -1, 26)
        out = []
        for ch in text:
            if "a" <= ch <= "z":
                base, upper = 97, False
            elif "A" <= ch <= "Z":
                base, upper = 65, True
            else:
                if not remove_punctuation:
                    out.append(ch)
                continue
            x = ord(ch) - base
            y = (inv * (x - b)) % 26 if decrypt else (a * x + b) % 26
            ch = chr(y + base)
            out.append(ch.upper() if upper else ch.lower())
        return "".join(out)

    def encode(self, text: str, **params) -> str:
        a, b = self._parse_key(params)
        return self._run(text, a, b, False,
                         _bool_param(params, "remove_punctuation", False))

    def decode(self, text: str, **params) -> str:
        a, b = self._parse_key(params)
        return self._run(text, a, b, True,
                         _bool_param(params, "remove_punctuation", False))


class RailFenceCodec(CodecBase):
    name = "栅栏密码"
    category = "古典密码"
    description = "栅栏密码,支持 W 型(之字形)和标准型(按下标取模分栏),栏数为参数"
    params = [
        ("rails", "栏数(>=2)", "3"),
        ("fence_type", "类型(W/标准型)", "W"),
    ]
    param_choices = {
        "fence_type": [
            ("W型(之字形)", "W"),
            ("标准型", "标准"),
        ],
    }

    def _rails(self, params: dict) -> int:
        try:
            rails = int(params.get("rails", "3"))
        except ValueError:
            raise CodecError("栏数必须是整数")
        if rails < 2:
            raise CodecError("栏数必须 >= 2")
        if rails > 10000:
            raise CodecError("栏数过大(最多 10000)")
        return rails

    @staticmethod
    def _fence_type(params: dict) -> str:
        raw = str(params.get("fence_type", "W")).strip().lower()
        if raw in ("w", "w型", "zigzag", "w-type"):
            return "w"
        if raw in ("standard", "标准", "标准型", "normal", "simple"):
            return "standard"
        raise CodecError("栅栏类型仅支持 W 或 标准")

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
        if self._fence_type(params) == "standard":
            # 标准型:第 i 个字符放入第 i % rails 栏,再按栏顺序读出
            for i, ch in enumerate(text):
                fence[i % rails].append(ch)
        else:
            for ch, r in zip(text, self._pattern(len(text), rails)):
                fence[r].append(ch)
        return "".join("".join(row) for row in fence)

    def decode(self, text: str, **params) -> str:
        rails = self._rails(params)
        n = len(text)
        if self._fence_type(params) == "standard":
            # 标准型:先算出每栏长度,切分密文后再按 i % rails 还原
            counts = [len(range(i, n, rails)) for i in range(rails)]
            rows = []
            idx = 0
            for c in counts:
                rows.append(list(text[idx:idx + c]))
                idx += c
            pos = [0] * rails
            out = []
            for i in range(n):
                r = i % rails
                out.append(rows[r][pos[r]])
                pos[r] += 1
            return "".join(out)

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
    description = (
        "按行写入 col 列网格,从最后一列开始蛇形(上下交替)读出;"
        "明文删去空格(空格不参与路径),密文中的空格同样忽略"
    )
    params = [
        ("cols", "列数(>=2)", "5"),
    ]

    def _cols(self, params: dict) -> int:
        try:
            cols = int(params.get("cols", "5"))
        except ValueError:
            raise CodecError("列数必须是整数")
        if cols < 2:
            raise CodecError("列数必须 >= 2")
        if cols > 10000:
            raise CodecError("列数过大(最多 10000)")
        return cols

    def encode(self, text: str, **params) -> str:
        cols = self._cols(params)
        text = re.sub(r"\s+", "", text)  # 空格不参与路径
        # 按行写入 col 列网格(第 i 个字符进第 i%cols 列)
        grid = [[] for _ in range(cols)]
        for i, ch in enumerate(text):
            grid[i % cols].append(ch)
        # 列顺序反转后,偶数位置的列内容再反转 => 从最后一列开始蛇形读出
        out = []
        for idx, col_chars in enumerate(reversed(grid)):
            if idx % 2 == 0:
                col_chars = col_chars[::-1]
            out.append("".join(col_chars))
        return "".join(out)

    def decode(self, text: str, **params) -> str:
        cols = self._cols(params)
        text = re.sub(r"\s+", "", text)  # 密文中用于分组的空格忽略
        n = len(text)
        min_row = n // cols          # 最短列的字符数
        min_num = cols - n % cols    # 最短列的个数(密文中排在前面)
        # 按加密时的输出顺序分组:短列在前,长列在后
        groups = []
        pos = 0
        for i in range(cols):
            size = min_row if i < min_num else min_row + 1
            groups.append(text[pos:pos + size])
            pos += size
        # 撤销偶数位置反转,再恢复原始列顺序
        for i in range(cols):
            if i % 2 == 0:
                groups[i] = groups[i][::-1]
        groups.reverse()
        # 按行读出
        return "".join(groups[i % cols][i // cols] for i in range(n))


class BaconCodec(CodecBase):
    name = "培根密码"
    category = "古典密码"
    description = "标准 24 字母表(A/B 五位一组,I/J、U/V 合并);兼容 0/1 输入"

    # 标准 24 字母表:去掉 J、U 后连续编号,而不是保留原 26 字母下标
    _ALPHABET = "ABCDEFGHIKLMNOPQRSTVWXYZ"
    _TABLE = {ch: format(i, "05b").replace("0", "A").replace("1", "B")
              for i, ch in enumerate(_ALPHABET)}
    _NORMALIZE = {"J": "I", "U": "V"}

    def encode(self, text: str, **p) -> str:
        if not text:
            return ""
        out = []
        for ch in text.upper():
            if ch.isspace():
                out.append("/")
            else:
                ch = self._NORMALIZE.get(ch, ch)
                if ch not in self._TABLE:
                    raise CodecError(f"培根密码仅支持英文字母和空白,遇到:{ch!r}")
                out.append(self._TABLE[ch])
        return " ".join(out)

    def decode(self, text: str, **p) -> str:
        if not text.strip():
            return ""
        rev = {v: k for k, v in self._TABLE.items()}
        # '/' 表示单词间空格;其余非 AB01 字符(如分组空格)忽略
        parts = text.upper().split("/")
        words = []
        for part in parts:
            cleaned = "".join(c for c in part if c in "AB01")
            if not cleaned:
                words.append("")
                continue
            cleaned = cleaned.replace("0", "A").replace("1", "B")
            if len(cleaned) % 5:
                raise CodecError(f"培根码长度({len(cleaned)})不是 5 的整数倍")
            chars = []
            for i in range(0, len(cleaned), 5):
                group = cleaned[i:i + 5]
                if group not in rev:
                    raise CodecError(f"无法识别的培根码组:{group!r}")
                chars.append(rev[group])
            words.append("".join(chars))
        return " ".join(words)


class MorseCodec(CodecBase):
    name = "摩斯电码"
    category = "古典密码"
    description = (
        "字母间空格分隔,单词间用 / 或多个空格;支持 {} 和扩展括号码,"
        "解码默认小写;restore_spaces=1 会尝试还原 flag 内被浏览器省略的空格"
    )
    params = [
        ("letter_case", "输出大小写(lower/upper)", "lower"),
        ("restore_spaces", "还原单词空格(1/0)", "1"),
    ]
    param_choices = {
        "letter_case": [
            ("小写(lower)", "lower"),
            ("大写(upper)", "upper"),
        ],
        "restore_spaces": [
            ("开启(1)", "1"),
            ("关闭(0)", "0"),
        ],
    }

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
        # 浏览器在线 Morse 工具的括号映射(实测)
        "{": "----.--", "}": "-----.-",
    }
    # 常见扩展括号码(不同工具/表可能不同);解码时统一当作括号占位符,
    # 再按出现顺序还原成 { / }。
    _BRACE_CODES = {"----.--", "-----.-", ".--.-", ".--.--", "----.-"}

    # 浏览器 Morse 会丢掉单词空格;这里用一个很小的词表做启发式还原。
    _RESTORE_WORDS = {
        "welcome", "come", "to", "the", "and", "is", "of", "in", "this", "that",
        "hello", "world", "flag", "ctf", "good", "luck", "secret", "key",
        "password", "decode", "encode", "misc", "easy", "hard",
    }
    _RESTORE_WORD_LIST = tuple(sorted(_RESTORE_WORDS, key=len, reverse=True))
    _BRACE_MARK = "\x00"

    @staticmethod
    def _letter_case(params: dict) -> str:
        raw = str(params.get("letter_case", "lower")).strip().lower()
        if raw not in ("lower", "upper"):
            raise CodecError("摩斯电码输出大小写仅支持 lower 或 upper")
        return raw

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

    @staticmethod
    def _fill_braces(text: str) -> str:
        positions = [i for i, ch in enumerate(text) if ch == MorseCodec._BRACE_MARK]
        if not positions:
            return text
        chars = list(text)
        if len(positions) == 1:
            i = positions[0]
            chars[i] = "}" if i > len(text) // 2 else "{"
        else:
            for n, i in enumerate(positions):
                chars[i] = "{" if n % 2 == 0 else "}"
        return "".join(chars)

    @classmethod
    def _segment_words(cls, s: str) -> list[str] | None:
        n = len(s)

        @lru_cache(maxsize=None)
        def dfs(i: int):
            if i == n:
                return ()
            for word in cls._RESTORE_WORD_LIST:
                upper = word.upper()
                if s.startswith(upper, i):
                    tail = dfs(i + len(upper))
                    if tail is not None:
                        return (word,) + tail
            return None

        result = dfs(0)
        return list(result) if result is not None else None

    @classmethod
    def _restore_spaces(cls, s: str) -> str:
        """还原浏览器工具省略的 flag 单词空格(启发式,只处理常见词)。"""
        if " " in s:
            return s
        match = re.fullmatch(r"(?i)(flag|ctf|key)\{([a-z]+)\}", s)
        if not match:
            return s
        words = cls._segment_words(match.group(2).upper())
        if not words:
            return s
        return f"{match.group(1).lower()}{{{' '.join(w.lower() for w in words)}}}"

    def decode(self, text: str, **p) -> str:
        rev = {v: k for k, v in self._TABLE.items() if k not in "{}"}
        for code in self._BRACE_CODES:
            rev[code] = self._BRACE_MARK
        text = text.strip()
        if not text:
            return ""
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
        result = self._fill_braces(" ".join(out))
        if _bool_param(p, "restore_spaces", True):
            result = self._restore_spaces(result)
        return result.lower() if self._letter_case(p) == "lower" else result.upper()


class PigpenCodec(CodecBase):
    name = "猪圈密码"
    category = "古典密码"
    description = (
        "标准猪圈密码符号(A-I 九宫格、J-R 九宫格带点、S-V X 形网格、W-Z X 形带点);"
        "支持斜杠/空格/不分隔三种符号分隔,以及是否保留非字母字符"
    )
    params = [
        ("separator", "符号分隔", "/"),
        ("keep_nonletters", "保留非字母字符", "0"),
    ]
    param_choices = {
        "separator": [
            ("斜杠 /", "/"),
            ("空格", " "),
            ("不分隔", ""),
        ],
    }
    param_bool = {"keep_nonletters"}

    # 标准猪圈密码对照表:
    # A-I 九宫格(无点),J-R 同形加中点,S-V X 形网格,W-Z 同形加中点
    _TABLE = {
        "A": "┘", "B": "⊔", "C": "└",
        "D": "⊐", "E": "□", "F": "⊏",
        "G": "┐", "H": "⊓", "I": "┌",
        "J": "┘•", "K": "⊔•", "L": "└•",
        "M": "⊐•", "N": "□•", "O": "⊏•",
        "P": "┐•", "Q": "⊓•", "R": "┌•",
        "S": "∨", "T": ">", "U": "<", "V": "∧",
        "W": "∨•", "X": ">•", "Y": "<•", "Z": "∧•",
    }

    @staticmethod
    def _separator(params: dict) -> str:
        raw = params.get("separator", "/")
        if raw in ("/", "斜杠", "斜杠 /"):
            return "/"
        if raw in (" ", "空格", "space"):
            return " "
        if raw in ("", "不分隔", "none", "无"):
            return ""
        raise CodecError("符号分隔仅支持 斜杠 /、空格 或 不分隔")

    def encode(self, text: str, **params) -> str:
        sep = self._separator(params)
        keep = _bool_param(params, "keep_nonletters", False)
        tokens = []
        for ch in text.upper():
            if ch in self._TABLE:
                tokens.append(self._TABLE[ch])
            elif keep:
                tokens.append(ch)
        if not tokens:
            return ""
        return sep.join(tokens)

    def decode(self, text: str, **params) -> str:
        sep = self._separator(params)
        keep = _bool_param(params, "keep_nonletters", False)
        rev = {}
        for ch, sym in self._TABLE.items():
            rev.setdefault(sym, ch)
            # 兼容用中点/句点表示的点
            rev.setdefault(sym.replace("•", "·"), ch)
            rev.setdefault(sym.replace("•", "."), ch)
        if not text:
            return ""

        if sep:
            parts = text.split(sep)
            out = []
            for part in parts:
                token = part.strip() if sep == " " else part
                if not token:
                    if keep and part:
                        out.append(part)
                    continue
                if token in rev:
                    out.append(rev[token])
                elif keep:
                    out.append(token)
                else:
                    raise CodecError(f"无法识别的猪圈符号:{token!r}")
            return "".join(out)

        # 不分隔:按最长符号贪心匹配
        symbols = sorted(rev, key=len, reverse=True)
        out = []
        i = 0
        while i < len(text):
            for sym in symbols:
                if text.startswith(sym, i):
                    out.append(rev[sym])
                    i += len(sym)
                    break
            else:
                if keep:
                    out.append(text[i])
                    i += 1
                else:
                    raise CodecError(f"无法识别的猪圈符号:{text[i]!r}")
        return "".join(out)
